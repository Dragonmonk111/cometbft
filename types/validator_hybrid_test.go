package types

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/crypto/hybrid"
	"github.com/cometbft/cometbft/crypto/mldsa44"
	"github.com/cometbft/cometbft/crypto/tmhash"
	cmtrand "github.com/cometbft/cometbft/libs/rand"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
)

// Project Aegis Phase F / ADR-008 §F5: the validator set must store and verify a
// hybrid (Ed25519 + ML-DSA-44) consensus pubkey transparently, and the validator
// Address must be INVARIANT across a PQ-half rotation so that all
// ValidatorAddress -> PubKey lookups in state continue to work with no migration.
//
// These tests exercise only the type-level + verification + rotation layer, which
// is protoc-free. The protobuf crypto/encoding oneof variant (over-the-wire /
// genesis / state-store persistence) is gated with F7 (needs protoc/buf).

// hybridPrecommit builds a precommit vote signed by priv and returns the vote
// plus the chainID it was signed under.
func hybridPrecommit(t *testing.T, priv hybrid.PrivKey, valAddr Address) (*Vote, string) {
	t.Helper()
	const chainID = "aegis-f5-chain"
	blockID := BlockID{Hash: cmtrand.Bytes(tmhash.Size), PartSetHeader: PartSetHeader{}}
	vote := &Vote{
		ValidatorAddress: valAddr,
		ValidatorIndex:   0,
		Height:           10,
		Round:            1,
		Type:             cmtproto.PrevoteType, // prevote: no vote-extension signing path
		BlockID:          blockID,
		Timestamp:        time.Now(),
	}
	v := vote.ToProto()
	sig, err := priv.Sign(VoteSignBytes(chainID, v))
	require.NoError(t, err)
	vote.Signature = sig
	return vote, chainID
}

// TestValidatorSetHoldsHybridPubKey proves a hybrid pubkey is a first-class
// crypto.PubKey: the set validates it, derives the classical-delegated address,
// and resolves it by address and index.
func TestValidatorSetHoldsHybridPubKey(t *testing.T) {
	priv := hybrid.GenPrivKey()
	pub := priv.PubKey()

	val := NewValidator(pub, 10)
	require.NoError(t, val.ValidateBasic(), "hybrid validator must pass ValidateBasic")
	require.Equal(t, hybrid.KeyType, val.PubKey.Type())

	// Address is the Ed25519-delegated address (zero state migration, §F1-b).
	edHalf := ed25519.PubKey(pub.Bytes()[:ed25519.PubKeySize])
	assert.Equal(t, edHalf.Address().Bytes(), val.Address.Bytes(),
		"hybrid validator address must equal its Ed25519 half's address")

	vs := NewValidatorSet([]*Validator{val})
	require.NoError(t, vs.ValidateBasic())

	idx, got := vs.GetByAddress(pub.Address())
	require.NotNil(t, got, "validator must be resolvable by its hybrid address")
	assert.Equal(t, int32(0), idx)
	assert.Equal(t, hybrid.KeyType, got.PubKey.Type())

	addr, gotByIdx := vs.GetByIndex(0)
	require.NotNil(t, gotByIdx)
	assert.Equal(t, pub.Address().Bytes(), Address(addr).Bytes())

	// NOTE (ADR-008 §F5-proto, gated on protoc/buf): vs.Hash(), Validator.Bytes()
	// and Validator.ToProto() serialize the pubkey through the protobuf
	// pc.PublicKey oneof (crypto/encoding.PubKeyToProto). The hybrid oneof variant
	// is added with the F7 proto regeneration; this type-level test deliberately
	// exercises only the protoc-free address/lookup/verification surface.
}

// TestHybridVoteVerifiesThroughValidatorSet proves a vote signed by the hybrid
// key verifies through exactly the path vote_set.go uses (val.PubKey.Verify),
// and that the classical-only Ed25519 half rejects the hybrid signature.
func TestHybridVoteVerifiesThroughValidatorSet(t *testing.T) {
	priv := hybrid.GenPrivKey()
	pub := priv.PubKey()
	val := NewValidator(pub, 10)

	vote, chainID := hybridPrecommit(t, priv, pub.Address())
	require.Len(t, vote.Signature, hybrid.SignatureSize)

	// Positive: the set's stored hybrid pubkey accepts the vote.
	require.NoError(t, vote.Verify(chainID, val.PubKey),
		"hybrid pubkey in the validator set must verify the hybrid vote")

	// Negative: a classical-only verifier (the Ed25519 half alone) must reject
	// the hybrid signature — the address matches but the framing/length does not.
	edHalf := ed25519.PubKey(pub.Bytes()[:ed25519.PubKeySize])
	require.Error(t, vote.Verify(chainID, edHalf),
		"classical-only verifier must reject a hybrid signature")
}

// TestHybridRotationPreservesAddress is the core §F5 invariant: rotating the
// ML-DSA-44 half while keeping the Ed25519 half yields a NEW key (the PQ trust
// anchor moved) but the SAME validator address, so the set keyed by address is
// undisturbed. A vote from the rotated key verifies under the new pubkey but is
// REJECTED by the pre-rotation pubkey, proving the PQ half actually rotated.
func TestHybridRotationPreservesAddress(t *testing.T) {
	priv1 := hybrid.GenPrivKey()
	pub1 := priv1.PubKey()

	// Rotate: reuse the Ed25519 half, swap in a fresh ML-DSA-44 half.
	edHalf := ed25519.PrivKey(append([]byte(nil), priv1.Bytes()[:ed25519.PrivateKeySize]...))
	ml2 := mldsa44.GenPrivKey()
	priv2, err := hybrid.NewPrivKeyFromHalves(edHalf, ml2)
	require.NoError(t, err)
	pub2 := priv2.PubKey()

	// Identity invariant: address unchanged, key changed.
	assert.Equal(t, pub1.Address().Bytes(), pub2.Address().Bytes(),
		"rotation must preserve the validator address (zero state migration)")
	assert.False(t, pub1.Equals(pub2), "rotation must actually change the hybrid key")

	// Set keyed by address is undisturbed by swapping the validator entry.
	val1 := NewValidator(pub1, 10)
	vs := NewValidatorSet([]*Validator{val1})
	require.NoError(t, vs.UpdateWithChangeSet([]*Validator{NewValidator(pub2, 10)}))
	_, got := vs.GetByAddress(pub1.Address())
	require.NotNil(t, got, "address lookup must still resolve after rotation")
	assert.Equal(t, pub2.Bytes(), got.PubKey.Bytes(), "set must now hold the rotated pubkey")

	// A vote from the rotated key verifies under the new key...
	vote, chainID := hybridPrecommit(t, priv2, pub2.Address())
	require.NoError(t, vote.Verify(chainID, pub2))

	// ...but is REJECTED by the pre-rotation key: same address, but the old
	// ML-DSA-44 half cannot verify a signature from the new one.
	require.Error(t, vote.Verify(chainID, pub1),
		"pre-rotation pubkey must reject a post-rotation signature (PQ half rotated)")
}
