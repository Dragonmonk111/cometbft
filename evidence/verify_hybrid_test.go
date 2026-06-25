package evidence_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cometbft/cometbft/crypto/hybrid"
	"github.com/cometbft/cometbft/evidence"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cometbft/cometbft/types"
)

// Project Aegis Phase F / ADR-008 §F5 + §6 checklist item 11: slashability with
// hybrid consensus keys, exercised through the REAL evidence verifier
// (evidence.VerifyDuplicateVote — the function a node calls before slashing).
//
// Property: DuplicateVoteEvidence is slashable iff BOTH halves of BOTH votes
// verify. A genuine hybrid double-sign IS slashable (the actually-malicious
// validator is punished). But a forged double-sign in which only the classical
// Ed25519 half is valid — exactly what a quantum attacker who broke ONLY Ed25519
// could fabricate to FRAME an honest validator — is REJECTED, because the
// ML-DSA-44 half does not verify. Hybrid keys make slashing strictly stronger:
// fabricating slashable evidence now also requires breaking ML-DSA-44.

func TestVerifyDuplicateVoteHybridSlashable(t *testing.T) {
	const (
		chainID = "aegis-evidence-chain"
		height  = int64(10)
		round   = int32(1)
	)

	hv := types.NewMockPVWithParams(hybrid.GenPrivKey(), false, false)
	pub, err := hv.GetPubKey()
	require.NoError(t, err)
	require.Equal(t, hybrid.KeyType, pub.Type(), "validator must use a hybrid consensus key")

	valSet := types.NewValidatorSet([]*types.Validator{hv.ExtractIntoValidator(10)})

	blockID1 := makeBlockID([]byte("aegis-hybrid-block-one"), 1000, []byte("parts-one"))
	blockID2 := makeBlockID([]byte("aegis-hybrid-block-two"), 1000, []byte("parts-two"))

	// Two conflicting precommits at the same H/R/S, each signed with both halves.
	voteA := types.MakeVoteNoError(t, hv, chainID, 0, height, round, cmtproto.PrecommitType, blockID1, defaultEvidenceTime)
	voteB := types.MakeVoteNoError(t, hv, chainID, 0, height, round, cmtproto.PrecommitType, blockID2, defaultEvidenceTime)
	require.Len(t, voteA.Signature, hybrid.SignatureSize)
	require.Len(t, voteB.Signature, hybrid.SignatureSize)

	// (1) Genuine hybrid double-sign => evidence is valid => validator slashable.
	ev, err := types.NewDuplicateVoteEvidence(voteA, voteB, defaultEvidenceTime, valSet)
	require.NoError(t, err)
	require.NoError(t, evidence.VerifyDuplicateVote(ev, chainID, valSet),
		"a genuine hybrid double-sign must be slashable")

	// (2) Forged double-sign with only the classical half intact: corrupt the
	// trailing ML-DSA-44 bytes of one vote while leaving the Ed25519 half
	// untouched (an attacker who broke ONLY Ed25519). The hybrid pubkey rejects
	// it, so the fabricated evidence cannot slash the honest validator.
	forgedVote := *ev.VoteB
	corruptSig := bytes.Clone(ev.VoteB.Signature)
	corruptSig[len(corruptSig)-1] ^= 0xFF // flip a byte inside the ML-DSA-44 half
	forgedVote.Signature = corruptSig
	require.NotEqual(t, ev.VoteB.Signature, forgedVote.Signature)

	forgedEv := &types.DuplicateVoteEvidence{
		VoteA:            ev.VoteA,
		VoteB:            &forgedVote,
		ValidatorPower:   ev.ValidatorPower,
		TotalVotingPower: ev.TotalVotingPower,
		Timestamp:        ev.Timestamp,
	}
	err = evidence.VerifyDuplicateVote(forgedEv, chainID, valSet)
	require.Error(t, err,
		"a forged double-sign with a broken ML-DSA-44 half must be rejected (honest validator protected)")
	require.ErrorIs(t, err, types.ErrVoteInvalidSignature)
}
