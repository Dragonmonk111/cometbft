// Package mldsa44 implements CometBFT's crypto.PubKey / crypto.PrivKey for a
// pure ML-DSA-44 (FIPS 204, NIST category 2) consensus key. It is the
// post-quantum half used by the hybrid consensus key (Project Aegis Phase F /
// ADR-008 §F1-a). It uses cloudflare/circl's ML-DSA-44 — the SAME vendored
// implementation already proven in transport (ADR-006) and accounts (ADR-007),
// so no new signature scheme enters the trust base.
//
// Determinism: ML-DSA-44 verification is integer-only and deterministic, which
// is the non-negotiable consensus-safety property (ADR-008 §6). Signing is
// hedged (uses rand) — nothing on-chain depends on signature bytes being
// deterministic, only on verification being deterministic.
//
// Key storage: a PrivKey is the 32-byte FIPS 204 seed; the expanded private key
// is reconstructed deterministically via ML-DSA.KeyGen on demand. This keeps the
// on-disk (FilePV sidecar) representation small and reproducible.
package mldsa44

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/subtle"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"

	cmtcrypto "github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/crypto/tmhash"
	cmtjson "github.com/cometbft/cometbft/libs/json"
)

const (
	PrivKeyName = "aegis/PrivKeyMlDsa44"
	PubKeyName  = "aegis/PubKeyMlDsa44"

	// PubKeySize is the size, in bytes, of an ML-DSA-44 public key (FIPS 204).
	PubKeySize = mldsa44.PublicKeySize // 1312
	// SignatureSize is the size, in bytes, of an ML-DSA-44 signature.
	SignatureSize = mldsa44.SignatureSize // 2420
	// SeedSize is the size, in bytes, of the deterministic key seed.
	SeedSize = mldsa44.SeedSize // 32

	KeyType = "mldsa44"
)

var (
	_ cmtcrypto.PrivKey = PrivKey{}
	_ cmtcrypto.PubKey  = PubKey{}
)

func init() {
	cmtjson.RegisterType(PubKey{}, PubKeyName)
	cmtjson.RegisterType(PrivKey{}, PrivKeyName)
}

// GenPrivKey generates a fresh random ML-DSA-44 private key (seed form).
func GenPrivKey() PrivKey {
	seed := make([]byte, SeedSize)
	if _, err := rand.Read(seed); err != nil {
		panic(fmt.Errorf("aegis mldsa44: read entropy: %w", err))
	}
	return PrivKey(seed)
}

// GenPrivKeyFromSeed builds a deterministic ML-DSA-44 private key from a 32-byte
// seed. Used by the HD / genesis-reproducible path.
func GenPrivKeyFromSeed(seed []byte) (PrivKey, error) {
	if len(seed) != SeedSize {
		return nil, fmt.Errorf("aegis mldsa44: seed must be %d bytes, got %d", SeedSize, len(seed))
	}
	return PrivKey(bytes.Clone(seed)), nil
}

// PrivKey is a 32-byte ML-DSA-44 seed. The expanded FIPS 204 private key is
// derived deterministically on use.
type PrivKey []byte

func (privKey PrivKey) expand() *mldsa44.PrivateKey {
	var seed [SeedSize]byte
	copy(seed[:], privKey)
	_, sk := mldsa44.NewKeyFromSeed(&seed)
	return sk
}

// Bytes returns the 32-byte seed.
func (privKey PrivKey) Bytes() []byte { return bytes.Clone(privKey) }

// Sign produces a 2420-byte ML-DSA-44 signature over msg.
func (privKey PrivKey) Sign(msg []byte) ([]byte, error) {
	if len(privKey) != SeedSize {
		return nil, fmt.Errorf("aegis mldsa44: uninitialized priv key (len %d)", len(privKey))
	}
	sig, err := privKey.expand().Sign(rand.Reader, msg, crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("aegis mldsa44: sign: %w", err)
	}
	return sig, nil
}

// PubKey returns the 1312-byte ML-DSA-44 public key.
func (privKey PrivKey) PubKey() cmtcrypto.PubKey {
	pub, err := privKey.expand().Public().(*mldsa44.PublicKey).MarshalBinary()
	if err != nil {
		panic(fmt.Errorf("aegis mldsa44: marshal pubkey: %w", err))
	}
	return PubKey(pub)
}

// Equals runs in constant time over the seeds.
func (privKey PrivKey) Equals(other cmtcrypto.PrivKey) bool {
	if other.Type() != KeyType {
		return false
	}
	return subtle.ConstantTimeCompare(privKey.Bytes(), other.Bytes()) == 1
}

func (privKey PrivKey) Type() string { return KeyType }

// PubKey is a 1312-byte FIPS 204 ML-DSA-44 public key.
type PubKey []byte

// Address is tmhash.SumTruncated(pubkey) — a 20-byte address in a distinct
// space from Ed25519. The hybrid key (F1-b) delegates Address() to its
// classical half so existing validator lookups are unaffected.
func (pubKey PubKey) Address() cmtcrypto.Address {
	if len(pubKey) != PubKeySize {
		panic(fmt.Sprintf("aegis mldsa44: invalid pubkey length %d, want %d", len(pubKey), PubKeySize))
	}
	return cmtcrypto.Address(tmhash.SumTruncated(pubKey))
}

// Bytes returns the marshaled public key.
func (pubKey PubKey) Bytes() []byte { return bytes.Clone(pubKey) }

// VerifySignature returns true iff sig is a valid ML-DSA-44 signature over msg.
// Verification is integer-only and deterministic (consensus-safe).
func (pubKey PubKey) VerifySignature(msg, sig []byte) bool {
	if len(pubKey) != PubKeySize || len(sig) != SignatureSize {
		return false
	}
	pub := new(mldsa44.PublicKey)
	if err := pub.UnmarshalBinary(pubKey); err != nil {
		return false
	}
	return mldsa44.Scheme().Verify(pub, msg, sig, nil)
}

func (pubKey PubKey) Equals(other cmtcrypto.PubKey) bool {
	if other.Type() != KeyType {
		return false
	}
	return bytes.Equal(pubKey.Bytes(), other.Bytes())
}

func (pubKey PubKey) Type() string { return KeyType }

func (pubKey PubKey) String() string {
	return fmt.Sprintf("PubKeyMlDsa44{%X}", []byte(pubKey))
}
