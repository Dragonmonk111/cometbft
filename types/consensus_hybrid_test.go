package types

import (
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cometbft/cometbft/crypto/batch"
	"github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/crypto/hybrid"
	cmtmath "github.com/cometbft/cometbft/libs/math"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
)

// Project Aegis Phase F / ADR-008 §F4 + §6 checklist item 9.
//
// These tests prove the migration thesis ("brownfield PQC — upgrade without
// halting"): a live ValidatorSet may hold a MIX of classical Ed25519 and hybrid
// (Ed25519 + ML-DSA-44) consensus keys; every node verifies every signature by
// resolving each signer's registered key type from state; and the chain reaches
// the 2/3 commit quorum with no coordinated halt. They drive the REAL
// VerifyCommit / VerifyCommitExtended consensus path (not a crypto-only shim),
// so they also cover the batch-verification gate (item 8): ML-DSA-44 has no
// batch verifier, so hybrid/mixed sets must fall back to single verification.

const hybridChainID = "test_chain_id"

// newHybridMockPV returns a PrivValidator backed by a fresh hybrid consensus key.
func newHybridMockPV() PrivValidator {
	return NewMockPVWithParams(hybrid.GenPrivKey(), false, false)
}

// makeMixedExtVoteSet builds an EXTENDED vote set over a validator set whose key
// types are dictated by isHybrid[i] (true => hybrid, false => classical
// Ed25519). All validators carry equal power, so NewValidatorSet orders them by
// address; we sort the PrivValidator slice the same way (exactly what
// RandValidatorSet relies on) so ValidatorIndex assignments line up.
func makeMixedExtVoteSet(t *testing.T, height int64, round int32, isHybrid []bool) (*VoteSet, *ValidatorSet, []PrivValidator) {
	t.Helper()
	privs := make([]PrivValidator, len(isHybrid))
	for i, h := range isHybrid {
		if h {
			privs[i] = newHybridMockPV()
		} else {
			privs[i] = NewMockPV() // classical ed25519
		}
	}
	return extVoteSetFromPrivs(t, height, round, privs)
}

// extVoteSetFromPrivs builds an EXTENDED vote set + validator set (equal power
// 10) from explicit PrivValidators. The returned slice is address-sorted to
// match valSet ordering — letting callers share the same PrivValidator across
// two different sets (needed to model IBC validator-set rotation).
func extVoteSetFromPrivs(t *testing.T, height int64, round int32, privs []PrivValidator) (*VoteSet, *ValidatorSet, []PrivValidator) {
	t.Helper()
	ordered := append([]PrivValidator(nil), privs...)
	// Match the address-ascending order NewValidatorSet uses for equal power.
	sort.Sort(PrivValidatorsByAddress(ordered))

	vals := make([]*Validator, len(ordered))
	for i, pv := range ordered {
		pub, err := pv.GetPubKey()
		require.NoError(t, err)
		vals[i] = NewValidator(pub, 10)
	}
	valSet := NewValidatorSet(vals)
	voteSet := NewExtendedVoteSet(hybridChainID, height, round, cmtproto.PrecommitType, valSet)
	return voteSet, valSet, ordered
}

// countKeyTypes reports how many validators use each consensus key type.
func countKeyTypes(vals *ValidatorSet) (classical, hybridN int) {
	for _, v := range vals.Validators {
		switch v.PubKey.Type() {
		case ed25519.KeyType:
			classical++
		case hybrid.KeyType:
			hybridN++
		}
	}
	return classical, hybridN
}

// TestHybridHeterogeneousCommitVerifies: 2 classical + 2 hybrid validators, all
// signing, produce a Commit that verifies through BOTH the extended and the
// plain consensus paths. This is the core coexistence property — classical and
// hybrid validators live in one ValidatorSet and every signature checks out.
func TestHybridHeterogeneousCommitVerifies(t *testing.T) {
	const height, round = int64(3), int32(0)
	blockID := makeBlockIDRandom()

	voteSet, valSet, privs := makeMixedExtVoteSet(t, height, round, []bool{false, true, false, true})

	classical, hybridN := countKeyTypes(valSet)
	require.Equal(t, 2, classical, "expected 2 classical validators")
	require.Equal(t, 2, hybridN, "expected 2 hybrid validators")
	require.False(t, valSet.AllKeysHaveSameType(), "a mixed set must not report a single key type")

	extCommit, err := MakeExtCommit(blockID, height, round, voteSet, privs, time.Now(), true)
	require.NoError(t, err)

	// Extended path: verifies BOTH the hybrid consensus signature AND the hybrid
	// vote-extension signature for every signer.
	require.NoError(t, valSet.VerifyCommitExtended(hybridChainID, blockID, height, extCommit),
		"heterogeneous extended commit must verify")

	// Plain path (block validation): verifies the consensus signatures only.
	commit := extCommit.ToCommit()
	require.NoError(t, valSet.VerifyCommit(hybridChainID, blockID, height, commit),
		"heterogeneous plain commit must verify")

	// A mixed set cannot batch-verify (the batch verifier requires one key
	// type), so it must fall back to per-signature verification — the dispatch
	// that resolves each signer's key type from state.
	require.False(t, shouldBatchVerify(valSet, commit),
		"mixed-type set must fall back to single verification")
}

// TestHybridAllHybridCommitVerifies: a fully-migrated set (all hybrid). The set
// reports a single key type, but ML-DSA-44 advertises NO batch verifier, so the
// commit path MUST fall back to single verification rather than attempting (and
// failing) batch verify. This proves the batch gate is correct for hybrid keys.
func TestHybridAllHybridCommitVerifies(t *testing.T) {
	const height, round = int64(5), int32(0)
	blockID := makeBlockIDRandom()

	voteSet, valSet, privs := makeMixedExtVoteSet(t, height, round, []bool{true, true, true, true})

	require.True(t, valSet.AllKeysHaveSameType(), "an all-hybrid set reports one key type")
	require.False(t, batch.SupportsBatchVerifier(valSet.GetProposer().PubKey),
		"the ML-DSA-44 hybrid key must not advertise batch support")

	extCommit, err := MakeExtCommit(blockID, height, round, voteSet, privs, time.Now(), true)
	require.NoError(t, err)

	commit := extCommit.ToCommit()
	require.False(t, shouldBatchVerify(valSet, commit),
		"all-hybrid set must fall back to single verification (no batch verifier)")
	require.NoError(t, valSet.VerifyCommit(hybridChainID, blockID, height, commit),
		"all-hybrid commit must verify via single verification")
}

// TestHybridMixedQuorumWithAbsentValidator is the realistic mid-migration block:
// 2 classical + 2 hybrid, with ONE validator offline. The surviving 3 (always a
// mix of both key types — removing any single validator from a 2+2 set leaves at
// least one of each) carry 75% > 2/3 of the power, so the block commits. This is
// the exact ADR-008 §6 item-9 scenario: rotated and un-rotated validators reach
// quorum together with no chain halt.
func TestHybridMixedQuorumWithAbsentValidator(t *testing.T) {
	const height, round = int64(7), int32(0)
	blockID := makeBlockIDRandom()
	now := time.Now()

	voteSet, valSet, privs := makeMixedExtVoteSet(t, height, round, []bool{false, true, false, true})

	// Sign with every validator except the last one (which stays offline).
	const absent = 3
	signerTypes := map[string]bool{}
	for i := 0; i < len(privs); i++ {
		if i == absent {
			continue
		}
		pub, err := privs[i].GetPubKey()
		require.NoError(t, err)
		signerTypes[pub.Type()] = true
		vote := &Vote{
			ValidatorAddress: pub.Address(),
			ValidatorIndex:   int32(i),
			Height:           height,
			Round:            round,
			Type:             cmtproto.PrecommitType,
			BlockID:          blockID,
			Timestamp:        now,
		}
		added, err := signAddVote(privs[i], vote, voteSet)
		require.NoError(t, err)
		require.True(t, added)
	}
	// The surviving quorum must be genuinely heterogeneous.
	require.True(t, signerTypes[ed25519.KeyType] && signerTypes[hybrid.KeyType],
		"the 3-of-4 quorum must contain both a classical and a hybrid signer")

	extCommit := voteSet.MakeExtendedCommit(ABCIParams{VoteExtensionsEnableHeight: height})
	require.Equal(t, BlockIDFlagAbsent, extCommit.ExtendedSignatures[absent].BlockIDFlag,
		"the offline validator must be marked absent")

	commit := extCommit.ToCommit()
	require.NoError(t, valSet.VerifyCommit(hybridChainID, blockID, height, commit),
		"a 3-of-4 mixed quorum (one validator offline) must still commit the block")
}

// signMixedCommit signs blockID with the validators at the given indices (in
// valSet/privs order) and returns the resulting plain Commit; validators not in
// signIdx are left absent. Used to model partial participation in the light
// client paths below.
func signMixedCommit(t *testing.T, voteSet *VoteSet, privs []PrivValidator, blockID BlockID, height int64, round int32, signIdx []int) *Commit {
	t.Helper()
	now := time.Now()
	for _, i := range signIdx {
		pub, err := privs[i].GetPubKey()
		require.NoError(t, err)
		vote := &Vote{
			ValidatorAddress: pub.Address(),
			ValidatorIndex:   int32(i),
			Height:           height,
			Round:            round,
			Type:             cmtproto.PrecommitType,
			BlockID:          blockID,
			Timestamp:        now,
		}
		added, err := signAddVote(privs[i], vote, voteSet)
		require.NoError(t, err)
		require.True(t, added)
	}
	return voteSet.MakeExtendedCommit(ABCIParams{VoteExtensionsEnableHeight: height}).ToCommit()
}

// allIdx returns [0, 1, ..., len(privs)-1].
func allIdx(privs []PrivValidator) []int {
	idx := make([]int, len(privs))
	for i := range privs {
		idx[i] = i
	}
	return idx
}

// TestHybridLightClientVerifiesHeterogeneousCommit covers ADR-008 §6 item 10 for
// the adjacent-header light-client path. types.VerifyCommitLight (and its
// all-signatures variant) — the routines light/verifier.go and the IBC
// 07-tendermint client call — must verify a +2/3 commit produced by a mixed
// classical+hybrid validator set.
func TestHybridLightClientVerifiesHeterogeneousCommit(t *testing.T) {
	const height, round = int64(9), int32(0)
	blockID := makeBlockIDRandom()

	voteSet, valSet, privs := makeMixedExtVoteSet(t, height, round, []bool{false, true, false, true})
	commit := signMixedCommit(t, voteSet, privs, blockID, height, round, []int{0, 1, 2, 3})

	require.NoError(t, valSet.VerifyCommitLight(hybridChainID, blockID, height, commit),
		"light client must verify a heterogeneous +2/3 commit")
	require.NoError(t, valSet.VerifyCommitLightAllSignatures(hybridChainID, blockID, height, commit),
		"light client all-signatures check must verify a heterogeneous commit")
}

// TestHybridLightClientTrustingCountsHybridSigners covers ADR-008 §6 item 10 for
// the skipping-verification path used by IBC. types.VerifyCommitLightTrusting
// checks that trustLevel of the *trusted* (old) set signed an untrusted commit,
// where the commit comes from a rotated (new) set that only partially overlaps
// the trusted set. The overlap here is hybrid validators carried across the
// rotation — proving hybrid signers count toward the IBC trust threshold (and
// that a sub-threshold overlap is correctly rejected).
//
// Modelling note: a Commit can only be built when the *new* set reached +2/3, so
// every new set below signs in full; the trust math is driven entirely by how
// much of that commit overlaps the trusted set.
func TestHybridLightClientTrustingCountsHybridSigners(t *testing.T) {
	const height, round = int64(11), int32(0)
	trustLevel := cmtmath.Fraction{Numerator: 1, Denominator: 3}

	// Trusted (old) set: 2 hybrid + 2 classical, equal power 10 -> total 40.
	// Trust needed at 1/3 = 40/3 = 13.
	hA, hB := newHybridMockPV(), newHybridMockPV()
	_, trustedSet, _ := extVoteSetFromPrivs(t, height, round,
		[]PrivValidator{hA, hB, NewMockPV(), NewMockPV()})

	t.Run("two carried-over hybrid validators satisfy 1/3 trust", func(t *testing.T) {
		blockID := makeBlockIDRandom()
		// Rotated set keeps hA and hB; the other two are brand new.
		voteSet, _, privs := extVoteSetFromPrivs(t, height, round,
			[]PrivValidator{hA, hB, newHybridMockPV(), NewMockPV()})
		commit := signMixedCommit(t, voteSet, privs, blockID, height, round, allIdx(privs))

		// overlap = hA + hB = 20 > 13.
		require.NoError(t, trustedSet.VerifyCommitLightTrusting(hybridChainID, commit, trustLevel),
			"two carried-over hybrid validators (20/40) must satisfy a 1/3 trust level")
		require.NoError(t, trustedSet.VerifyCommitLightTrustingAllSignatures(hybridChainID, commit, trustLevel),
			"all-signatures trusting check must also pass")
	})

	t.Run("single carried-over hybrid validator is below 1/3 trust", func(t *testing.T) {
		blockID := makeBlockIDRandom()
		// Rotated set keeps only hA; the rest are brand new (no overlap).
		voteSet, _, privs := extVoteSetFromPrivs(t, height, round,
			[]PrivValidator{hA, newHybridMockPV(), NewMockPV(), newHybridMockPV()})
		commit := signMixedCommit(t, voteSet, privs, blockID, height, round, allIdx(privs))

		// overlap = hA = 10 <= 13.
		err := trustedSet.VerifyCommitLightTrusting(hybridChainID, commit, trustLevel)
		require.Error(t, err, "a single carried-over hybrid validator (10/40) must not satisfy a 1/3 trust level")
		require.True(t, IsErrNotEnoughVotingPowerSigned(err),
			"expected ErrNotEnoughVotingPowerSigned, got %v", err)
	})
}
