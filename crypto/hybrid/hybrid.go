// Package hybrid implements a Project Aegis Phase F / ADR-008 hybrid CONSENSUS
// key: an Ed25519 AND ML-DSA-44 (FIPS 204) key at once. A vote/proposal/commit
// signature is valid only if BOTH halves verify, so a validator is forgeable
// only if BOTH primitives are broken. Security is the stronger of the two.
//
// The classical half COMPOSES CometBFT's own crypto/ed25519 (identical wire
// format and ZIP-215 verification semantics to classical validators); the PQ
// half uses crypto/mldsa44 (cloudflare/circl ML-DSA-44).
//
// MIGRATION INVARIANT (ADR-008 §F1-b): Address() delegates to the Ed25519 half,
// so every ValidatorAddress -> PubKey lookup in state continues to work with NO
// state migration. The PQC half rides inside Bytes()/Type() only.
//
// Determinism (ADR-008 §6): VerifySignature is integer-only on the PQ half and
// ZIP-215 on the classical half — both deterministic across CPU/OS, the
// consensus-safety requirement.
package hybrid

import (
	"bytes"
	"encoding/binary"
	"fmt"

	cmtcrypto "github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/crypto/mldsa44"
	cmtjson "github.com/cometbft/cometbft/libs/json"
)

const (
	PrivKeyName = "aegis/PrivKeyHybridEd25519MlDsa44"
	PubKeyName  = "aegis/PubKeyHybridEd25519MlDsa44"

	// KeyType is the algorithm name reported by Type() and registered with the
	// proto/json codec.
	KeyType = "aegis-hybrid-ed25519-mldsa44"

	// Public key is ed25519(32) || mldsa44(1312) = 1344 bytes.
	PubKeySize = ed25519.PubKeySize + mldsa44.PubKeySize // 1344
	// Private key (seed form) is ed25519(64) || mldsa44-seed(32) = 96 bytes.
	PrivKeySize = ed25519.PrivateKeySize + mldsa44.SeedSize // 96

	// --- F2 versioned, algorithm-tagged signature wire format (ADR-008 §F2) ---
	sigVersion       = 0x01
	algoIDEd25519    = 0x01
	algoIDMlDsa44    = 0x02
	// classicalHeaderLen = version(1) + algo_id(1) + len(2); pqcHeaderLen omits
	// the version byte (it is global, set once at the front of the frame).
	classicalHeaderLen = 1 + 1 + 2 // 4
	pqcHeaderLen       = 1 + 2     // 3
	classicalSigLen    = ed25519.SignatureSize // 64
	pqcSigLen          = mldsa44.SignatureSize  // 2420
	// SignatureSize is the total hybrid signature size: 7 bytes of framing +
	// 64 + 2420 = 2491.
	SignatureSize = classicalHeaderLen + classicalSigLen + pqcHeaderLen + pqcSigLen
)

var (
	_ cmtcrypto.PrivKey = PrivKey{}
	_ cmtcrypto.PubKey  = PubKey{}
)

func init() {
	cmtjson.RegisterType(PubKey{}, PubKeyName)
	cmtjson.RegisterType(PrivKey{}, PrivKeyName)
}

// ---------------------------------------------------------------- F2 codec

// encodeHybridSig frames the two halves into the ADR-008 §F2 self-describing,
// crypto-agile wire format. Future schemes slot in via new algo IDs.
func encodeHybridSig(classical, pqc []byte) []byte {
	out := make([]byte, 0, SignatureSize)
	out = append(out, sigVersion, algoIDEd25519)
	out = binary.BigEndian.AppendUint16(out, uint16(len(classical)))
	out = append(out, classical...)
	out = append(out, algoIDMlDsa44)
	out = binary.BigEndian.AppendUint16(out, uint16(len(pqc)))
	out = append(out, pqc...)
	return out
}

// decodeHybridSig parses the §F2 frame. It is strict: unknown version/algo IDs
// or wrong lengths are rejected, so a classical-only verifier never
// mis-interprets a hybrid signature.
func decodeHybridSig(sig []byte) (classical, pqc []byte, ok bool) {
	if len(sig) != SignatureSize {
		return nil, nil, false
	}
	i := 0
	if sig[i] != sigVersion {
		return nil, nil, false
	}
	i++
	if sig[i] != algoIDEd25519 {
		return nil, nil, false
	}
	i++
	cLen := int(binary.BigEndian.Uint16(sig[i : i+2]))
	i += 2
	if cLen != classicalSigLen || i+cLen > len(sig) {
		return nil, nil, false
	}
	classical = sig[i : i+cLen]
	i += cLen
	if sig[i] != algoIDMlDsa44 {
		return nil, nil, false
	}
	i++
	pLen := int(binary.BigEndian.Uint16(sig[i : i+2]))
	i += 2
	if pLen != pqcSigLen || i+pLen != len(sig) {
		return nil, nil, false
	}
	pqc = sig[i : i+pLen]
	return classical, pqc, true
}

// ---------------------------------------------------------------- PrivKey

// GenPrivKey generates a fresh random hybrid consensus private key.
func GenPrivKey() PrivKey {
	ed := ed25519.GenPrivKey()
	ml := mldsa44.GenPrivKey()
	return composePriv(ed, ml)
}

// NewPrivKeyFromHalves builds a hybrid key from existing halves. Used to wrap an
// EXISTING ed25519 consensus key with a fresh/derived ML-DSA-44 half during
// rotation (ADR-008 §F6) without changing the validator address.
func NewPrivKeyFromHalves(ed ed25519.PrivKey, ml mldsa44.PrivKey) (PrivKey, error) {
	if len(ed) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("aegis hybrid: ed25519 priv must be %d bytes, got %d", ed25519.PrivateKeySize, len(ed))
	}
	if len(ml) != mldsa44.SeedSize {
		return nil, fmt.Errorf("aegis hybrid: mldsa44 seed must be %d bytes, got %d", mldsa44.SeedSize, len(ml))
	}
	return composePriv(ed, ml), nil
}

func composePriv(ed ed25519.PrivKey, ml mldsa44.PrivKey) PrivKey {
	out := make([]byte, 0, PrivKeySize)
	out = append(out, ed...)
	out = append(out, ml...)
	return PrivKey(out)
}

// PrivKey is ed25519-priv(64) || mldsa44-seed(32).
type PrivKey []byte

func (privKey PrivKey) halves() (ed25519.PrivKey, mldsa44.PrivKey) {
	ed := ed25519.PrivKey(privKey[:ed25519.PrivateKeySize])
	ml := mldsa44.PrivKey(privKey[ed25519.PrivateKeySize:])
	return ed, ml
}

func (privKey PrivKey) Bytes() []byte { return bytes.Clone(privKey) }

// Sign signs msg with BOTH halves and frames them per §F2.
func (privKey PrivKey) Sign(msg []byte) ([]byte, error) {
	if len(privKey) != PrivKeySize {
		return nil, fmt.Errorf("aegis hybrid: uninitialized priv key (len %d)", len(privKey))
	}
	ed, ml := privKey.halves()
	classicalSig, err := ed.Sign(msg)
	if err != nil {
		return nil, fmt.Errorf("aegis hybrid: ed25519 sign: %w", err)
	}
	pqcSig, err := ml.Sign(msg)
	if err != nil {
		return nil, fmt.Errorf("aegis hybrid: mldsa44 sign: %w", err)
	}
	return encodeHybridSig(classicalSig, pqcSig), nil
}

// PubKey returns the matching hybrid public key (ed25519(32) || mldsa44(1312)).
func (privKey PrivKey) PubKey() cmtcrypto.PubKey {
	ed, ml := privKey.halves()
	out := make([]byte, 0, PubKeySize)
	out = append(out, ed.PubKey().Bytes()...)
	out = append(out, ml.PubKey().Bytes()...)
	return PubKey(out)
}

func (privKey PrivKey) Equals(other cmtcrypto.PrivKey) bool {
	if other.Type() != KeyType {
		return false
	}
	return bytes.Equal(privKey.Bytes(), other.Bytes())
}

func (privKey PrivKey) Type() string { return KeyType }

// ---------------------------------------------------------------- PubKey

// PubKey is ed25519(32) || mldsa44(1312) = 1344 bytes.
type PubKey []byte

func (pubKey PubKey) halves() (ed25519.PubKey, mldsa44.PubKey) {
	ed := ed25519.PubKey(pubKey[:ed25519.PubKeySize])
	ml := mldsa44.PubKey(pubKey[ed25519.PubKeySize:])
	return ed, ml
}

// Address delegates to the Ed25519 half — IDENTICAL to the pre-migration
// address, so validator-set lookups need no state migration (ADR-008 §F1-b).
func (pubKey PubKey) Address() cmtcrypto.Address {
	if len(pubKey) != PubKeySize {
		panic(fmt.Sprintf("aegis hybrid: invalid pubkey length %d, want %d", len(pubKey), PubKeySize))
	}
	ed, _ := pubKey.halves()
	return ed.Address()
}

func (pubKey PubKey) Bytes() []byte { return bytes.Clone(pubKey) }

// VerifySignature returns true iff BOTH the Ed25519 and ML-DSA-44 halves verify
// over msg. A break of one primitive alone is insufficient to forge.
func (pubKey PubKey) VerifySignature(msg, sig []byte) bool {
	if len(pubKey) != PubKeySize {
		return false
	}
	classicalSig, pqcSig, ok := decodeHybridSig(sig)
	if !ok {
		return false
	}
	ed, ml := pubKey.halves()
	if !ed.VerifySignature(msg, classicalSig) {
		return false
	}
	return ml.VerifySignature(msg, pqcSig)
}

func (pubKey PubKey) Equals(other cmtcrypto.PubKey) bool {
	if other.Type() != KeyType {
		return false
	}
	return bytes.Equal(pubKey.Bytes(), other.Bytes())
}

func (pubKey PubKey) Type() string { return KeyType }

func (pubKey PubKey) String() string {
	return fmt.Sprintf("PubKeyHybridEd25519MlDsa44{%X}", []byte(pubKey))
}
