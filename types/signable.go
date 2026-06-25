package types

import (
	"github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/crypto/hybrid"
	cmtmath "github.com/cometbft/cometbft/libs/math"
)

var (
	// MaxSignatureSize is a maximum allowed signature size for the Proposal
	// and Vote.
	// XXX: secp256k1 does not have Size nor MaxSize defined.
	//
	// Project Aegis (ADR-008 §F2): a hybrid Ed25519+ML-DSA-44 consensus
	// signature is hybrid.SignatureSize (2,491 B = 7 B algorithm-tagged framing
	// + 64 B Ed25519 + 2,420 B ML-DSA-44), so the bound is raised to admit it.
	// This is the tightest value that accepts a valid hybrid Vote/Proposal/
	// CommitSig/vote-extension signature while still bounding per-signature
	// memory. The classical floor is retained for un-migrated validators.
	MaxSignatureSize = cmtmath.MaxInt(hybrid.SignatureSize, cmtmath.MaxInt(ed25519.SignatureSize, 64))
)

// Signable is an interface for all signable things.
// It typically removes signatures before serializing.
// SignBytes returns the bytes to be signed
// NOTE: chainIDs are part of the SignBytes but not
// necessarily the object themselves.
// NOTE: Expected to panic if there is an error marshaling.
type Signable interface {
	SignBytes(chainID string) []byte
}
