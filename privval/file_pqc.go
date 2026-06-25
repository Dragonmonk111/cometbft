// file_pqc.go extends FilePV with optional ML-DSA-44 sidecar support for
// Project Aegis Phase F (ADR-008 §F4).
//
// A validator can run in three modes:
//   1. Classical only  — no sidecar, behaves exactly like pre-migration FilePV.
//   2. Hybrid          — sidecar loaded; signs votes/proposals with both halves.
//   3. Transition      — sidecar can be atomically added to an existing FilePV
//                        (key file never rewritten, only sidecar created).
//
// The sidecar naming convention:
//   priv_validator_key.json   -> priv_validator_key_mldsa44.json
//
// This keeps the classical key file untouched, so a downgrade path exists:
// remove the sidecar file and the validator reverts to classical-only signing.
package privval

import (
	"fmt"
	"os"

	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/crypto/hybrid"
	"github.com/cometbft/cometbft/crypto/mldsa44"
	cmtjson "github.com/cometbft/cometbft/libs/json"
	cmtos "github.com/cometbft/cometbft/libs/os"
	"github.com/cometbft/cometbft/libs/tempfile"
	"github.com/cometbft/cometbft/types"
)

// FilePVKeyMlDsa44 is the sidecar that holds the post-quantum half of a
// hybrid consensus key. It is stored separately so the classical key file
// is never mutated during migration.
type FilePVKeyMlDsa44 struct {
	Address types.Address  `json:"address"`
	PubKey  crypto.PubKey  `json:"pub_key"`
	PrivKey crypto.PrivKey `json:"priv_key"`

	filePath string
}

// Save persists the sidecar to its filePath.
func (pvKey FilePVKeyMlDsa44) Save() {
	outFile := pvKey.filePath
	if outFile == "" {
		panic("cannot save PQC sidecar: filePath not set")
	}
	jsonBytes, err := cmtjson.MarshalIndent(pvKey, "", "  ")
	if err != nil {
		panic(err)
	}
	if err := tempfile.WriteFileAtomic(outFile, jsonBytes, 0600); err != nil {
		panic(err)
	}
}

// sidecarPath returns the conventional sidecar path for a given key file.
func sidecarPath(keyFilePath string) string {
	return keyFilePath + "_mldsa44.json"
}

// ------------------------------------------------------------------
// Hybrid-aware FilePV constructors
// ------------------------------------------------------------------

// GenFilePVWithPQC generates a fresh classical + ML-DSA-44 hybrid validator.
// The classical key is stored at keyFilePath; the PQC half at keyFilePath_mldsa44.json.
func GenFilePVWithPQC(keyFilePath, stateFilePath string) *FilePV {
	ed := ed25519.GenPrivKey()
	ml := mldsa44.GenPrivKey()

	pv := NewFilePV(ed, keyFilePath, stateFilePath)
	pv.PQCSidecar = &FilePVKeyMlDsa44{
		Address:  types.Address(ml.PubKey().Address()), // distinct PQC address space
		PubKey:   ml.PubKey(),
		PrivKey:  ml,
		filePath: sidecarPath(keyFilePath),
	}
	return pv
}

// LoadFilePVWithPQC loads a FilePV and, if a sidecar file exists alongside
// the key file, loads it too. If the sidecar is missing, behaves exactly like
// LoadFilePV (classical-only).
func LoadFilePVWithPQC(keyFilePath, stateFilePath string) *FilePV {
	pv := LoadFilePV(keyFilePath, stateFilePath)
	if cmtos.FileExists(sidecarPath(keyFilePath)) {
		pv.loadSidecar(sidecarPath(keyFilePath))
	}
	return pv
}

// LoadOrGenFilePVWithPQC loads from disk or generates a fresh hybrid key pair.
func LoadOrGenFilePVWithPQC(keyFilePath, stateFilePath string) *FilePV {
	var pv *FilePV
	if cmtos.FileExists(keyFilePath) && cmtos.FileExists(sidecarPath(keyFilePath)) {
		pv = LoadFilePVWithPQC(keyFilePath, stateFilePath)
	} else {
		pv = GenFilePVWithPQC(keyFilePath, stateFilePath)
		pv.Save()
	}
	return pv
}

// loadSidecar reads the ML-DSA-44 sidecar from disk and attaches it to the FilePV.
func (pv *FilePV) loadSidecar(sidecarFilePath string) {
	jsonBytes, err := os.ReadFile(sidecarFilePath)
	if err != nil {
		cmtos.Exit(fmt.Sprintf("Error reading PQC sidecar from %v: %v\n", sidecarFilePath, err))
	}
	sc := FilePVKeyMlDsa44{}
	if err := cmtjson.Unmarshal(jsonBytes, &sc); err != nil {
		cmtos.Exit(fmt.Sprintf("Error unmarshalling PQC sidecar from %v: %v\n", sidecarFilePath, err))
	}
	sc.filePath = sidecarFilePath
	// sanity: pubkey matches seed
	sc.PubKey = sc.PrivKey.PubKey()
	sc.Address = sc.PubKey.Address()
	pv.PQCSidecar = &sc
}

// ------------------------------------------------------------------
// Helper: hybrid signing key
// ------------------------------------------------------------------

// signingPrivKey returns the appropriate private key for signing:
//   - hybrid key when a PQC sidecar is present
//   - classical key otherwise (backward compatible)
func (pv *FilePV) signingPrivKey() crypto.PrivKey {
	if pv.PQCSidecar == nil {
		return pv.Key.PrivKey
	}
	hp, err := hybrid.NewPrivKeyFromHalves(
		pv.Key.PrivKey.(ed25519.PrivKey),
		pv.PQCSidecar.PrivKey.(mldsa44.PrivKey),
	)
	if err != nil {
		panic(fmt.Sprintf("aegis hybrid: impossible key composition: %v", err))
	}
	return hp
}
