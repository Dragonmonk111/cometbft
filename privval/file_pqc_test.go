package privval

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/crypto/hybrid"
	"github.com/cometbft/cometbft/crypto/tmhash"
	cmtrand "github.com/cometbft/cometbft/libs/rand"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cometbft/cometbft/types"
)

// newTestFilePVWithPQC mirrors newTestFilePV but builds a hybrid validator
// (Ed25519 + ML-DSA-44 sidecar) per ADR-008 §F4.
func newTestFilePVWithPQC(t *testing.T) (*FilePV, string, string) {
	t.Helper()
	tempKeyFile, err := os.CreateTemp(t.TempDir(), "priv_validator_key_")
	require.NoError(t, err)
	tempStateFile, err := os.CreateTemp(t.TempDir(), "priv_validator_state_")
	require.NoError(t, err)

	pv := GenFilePVWithPQC(tempKeyFile.Name(), tempStateFile.Name())
	return pv, tempKeyFile.Name(), tempStateFile.Name()
}

// TestHybridSignVote verifies that a hybrid FilePV signs votes with BOTH halves
// and that the resulting signature verifies under the hybrid pubkey, is the
// correct hybrid size, and is rejected by a classical-only verifier.
func TestHybridSignVote(t *testing.T) {
	pv, _, _ := newTestFilePVWithPQC(t)
	require.NotNil(t, pv.PQCSidecar, "expected PQC sidecar to be present")

	height, round := int64(10), int32(1)
	randBytes := cmtrand.Bytes(tmhash.Size)
	blockID := types.BlockID{Hash: randBytes, PartSetHeader: types.PartSetHeader{}}
	vote := newVote(pv.Key.Address, 0, height, round, cmtproto.PrecommitType, blockID, nil)
	voteProto := vote.ToProto()

	require.NoError(t, pv.SignVote("mychainid", voteProto))

	// Hybrid signature is the full framed size (7 B framing + 64 + 2420).
	require.Len(t, voteProto.Signature, hybrid.SignatureSize)

	signBytes := types.VoteSignBytes("mychainid", voteProto)

	// Hybrid pubkey accepts (both halves verify).
	hpk, err := pv.GetPubKey()
	require.NoError(t, err)
	assert.Equal(t, hybrid.KeyType, hpk.Type())
	assert.True(t, hpk.VerifySignature(signBytes, voteProto.Signature),
		"hybrid pubkey must accept a hybrid signature")

	// Classical-only verifier must reject the hybrid signature (framing/length mismatch).
	classicalPub := pv.Key.PrivKey.(ed25519.PrivKey).PubKey()
	assert.False(t, classicalPub.VerifySignature(signBytes, voteProto.Signature),
		"classical-only verifier must reject a hybrid signature")
}

// TestHybridSignProposal verifies the proposal path also signs with both halves.
func TestHybridSignProposal(t *testing.T) {
	pv, _, _ := newTestFilePVWithPQC(t)

	randBytes := cmtrand.Bytes(tmhash.Size)
	blockID := types.BlockID{Hash: randBytes, PartSetHeader: types.PartSetHeader{}}
	proposal := newProposal(10, 1, blockID)
	proposalProto := proposal.ToProto()

	require.NoError(t, pv.SignProposal("mychainid", proposalProto))
	require.Len(t, proposalProto.Signature, hybrid.SignatureSize)

	signBytes := types.ProposalSignBytes("mychainid", proposalProto)
	hpk, err := pv.GetPubKey()
	require.NoError(t, err)
	assert.True(t, hpk.VerifySignature(signBytes, proposalProto.Signature))
}

// TestHybridPersistReload verifies the sidecar persists and reloads, the
// classical key file is untouched, and the validator address is unchanged
// (ADR-008 §F1-b migration invariant).
func TestHybridPersistReload(t *testing.T) {
	pv, keyFile, stateFile := newTestFilePVWithPQC(t)
	addrBefore := pv.GetAddress()
	pv.Save()

	// Sidecar file must exist alongside the classical key file.
	_, err := os.Stat(sidecarPath(keyFile))
	require.NoError(t, err, "PQC sidecar file must be written next to the key file")

	reloaded := LoadFilePVWithPQC(keyFile, stateFile)
	require.NotNil(t, reloaded.PQCSidecar, "sidecar must reload")

	// Address is delegated to the classical half and must be unchanged.
	assert.Equal(t, addrBefore, reloaded.GetAddress(),
		"hybrid address must equal classical address (zero state migration)")

	// A vote signed after reload still verifies with the hybrid pubkey.
	blockID := types.BlockID{Hash: cmtrand.Bytes(tmhash.Size), PartSetHeader: types.PartSetHeader{}}
	vote := newVote(reloaded.Key.Address, 0, 11, 1, cmtproto.PrecommitType, blockID, nil)
	voteProto := vote.ToProto()
	require.NoError(t, reloaded.SignVote("mychainid", voteProto))

	hpk, err := reloaded.GetPubKey()
	require.NoError(t, err)
	assert.True(t, hpk.VerifySignature(types.VoteSignBytes("mychainid", voteProto), voteProto.Signature))
}

// TestClassicalPVUnaffected guards the backward-compatible path: a FilePV with
// no sidecar still signs classical-only and verifies under the Ed25519 pubkey.
func TestClassicalPVUnaffected(t *testing.T) {
	pv, _, _ := newTestFilePV(t)
	require.Nil(t, pv.PQCSidecar)

	blockID := types.BlockID{Hash: cmtrand.Bytes(tmhash.Size), PartSetHeader: types.PartSetHeader{}}
	vote := newVote(pv.Key.Address, 0, 10, 1, cmtproto.PrecommitType, blockID, nil)
	voteProto := vote.ToProto()
	require.NoError(t, pv.SignVote("mychainid", voteProto))

	require.Len(t, voteProto.Signature, ed25519.SignatureSize)
	pub, err := pv.GetPubKey()
	require.NoError(t, err)
	assert.True(t, pub.VerifySignature(types.VoteSignBytes("mychainid", voteProto), voteProto.Signature))
}
