// signer_client_pqc_test.go proves the remote-signer (SignerClient/SignerServer)
// path carries a full hybrid Ed25519+ML-DSA-44 consensus key and signature
// end-to-end over the real signer transport — Project Aegis Phase F (ADR-008,
// the "SignerClient hybrid" item left open after F4 wired only FilePV).
//
// The server wraps a hybrid FilePV (classical key file + ML-DSA-44 sidecar).
// The client retrieves the 1,344 B hybrid pubkey via the PubKey oneof and gets
// back 2,491 B framed hybrid signatures, both well under maxRemoteSignerMsgSize.
package privval

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/crypto/hybrid"
	"github.com/cometbft/cometbft/crypto/tmhash"
	cmtrand "github.com/cometbft/cometbft/libs/rand"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cometbft/cometbft/types"
)

// hybridSignerTestCase mirrors signerTestCase but wraps a hybrid FilePV on the
// server side instead of MockPV, so the remote-signer protocol must transport
// hybrid keys and signatures.
type hybridSignerTestCase struct {
	chainID      string
	serverPV     types.PrivValidator
	signerClient *SignerClient
	signerServer *SignerServer
}

func getHybridSignerTestCases(t *testing.T) []hybridSignerTestCase {
	t.Helper()
	testCases := make([]hybridSignerTestCase, 0)

	// One case per dialer transport (TCP / Unix), matching getSignerTestCases.
	for _, dtc := range getDialerTestCases(t) {
		chainID := cmtrand.Str(12)

		dir := t.TempDir()
		keyFile := filepath.Join(dir, "priv_validator_key.json")
		stateFile := filepath.Join(dir, "priv_validator_state.json")

		// Hybrid validator: classical key + ML-DSA-44 sidecar (in-memory is
		// enough; signing writes only the state file under the temp dir).
		serverPV := GenFilePVWithPQC(keyFile, stateFile)

		sl, sd := getMockEndpoints(t, dtc.addr, dtc.dialer)
		sc, err := NewSignerClient(sl, chainID)
		require.NoError(t, err)
		ss := NewSignerServer(sd, chainID, serverPV)
		require.NoError(t, ss.Start())

		testCases = append(testCases, hybridSignerTestCase{
			chainID:      chainID,
			serverPV:     serverPV,
			signerClient: sc,
			signerServer: ss,
		})
	}
	return testCases
}

func cleanupHybridCase(t *testing.T, tc hybridSignerTestCase) {
	t.Cleanup(func() {
		if err := tc.signerServer.Stop(); err != nil {
			t.Error(err)
		}
	})
	t.Cleanup(func() {
		if err := tc.signerClient.Close(); err != nil {
			t.Error(err)
		}
	})
}

// TestSignerHybridGetPubKey: the client retrieves the hybrid pubkey over the
// wire and it matches the server's, with the classical-half address invariant.
func TestSignerHybridGetPubKey(t *testing.T) {
	for _, tc := range getHybridSignerTestCases(t) {
		cleanupHybridCase(t, tc)

		pk, err := tc.signerClient.GetPubKey()
		require.NoError(t, err)
		require.Equal(t, hybrid.KeyType, pk.Type())
		require.Len(t, pk.Bytes(), hybrid.PubKeySize)

		expected, err := tc.serverPV.GetPubKey()
		require.NoError(t, err)
		require.True(t, pk.Equals(expected))
		// Address is the Ed25519-half address — zero state migration.
		require.Equal(t, expected.Address(), pk.Address())
	}
}

// TestSignerHybridVote: a vote signed via the remote signer carries a full
// 2,491 B framed hybrid signature that verifies under the hybrid pubkey and is
// rejected by a classical-only Ed25519 verifier.
func TestSignerHybridVote(t *testing.T) {
	for _, tc := range getHybridSignerTestCases(t) {
		cleanupHybridCase(t, tc)

		pk, err := tc.signerClient.GetPubKey()
		require.NoError(t, err)

		hash := cmtrand.Bytes(tmhash.Size)
		vote := &types.Vote{
			Type:             cmtproto.PrecommitType,
			Height:           1,
			Round:            2,
			BlockID:          types.BlockID{Hash: hash, PartSetHeader: types.PartSetHeader{Hash: hash, Total: 2}},
			Timestamp:        time.Now(),
			ValidatorAddress: cmtrand.Bytes(crypto.AddressSize),
			ValidatorIndex:   1,
		}

		votePb := vote.ToProto()
		require.NoError(t, tc.signerClient.SignVote(tc.chainID, votePb))

		signBytes := types.VoteSignBytes(tc.chainID, votePb)
		require.Len(t, votePb.Signature, hybrid.SignatureSize)
		require.True(t, pk.VerifySignature(signBytes, votePb.Signature))

		// A classical-only verifier (Ed25519 half alone) must reject the
		// framed hybrid signature — proves no silent downgrade on the wire.
		edHalf := ed25519.PubKey(pk.Bytes()[:ed25519.PubKeySize])
		require.False(t, edHalf.VerifySignature(signBytes, votePb.Signature))
	}
}

// TestSignerHybridProposal: same end-to-end guarantee for proposals.
func TestSignerHybridProposal(t *testing.T) {
	for _, tc := range getHybridSignerTestCases(t) {
		cleanupHybridCase(t, tc)

		pk, err := tc.signerClient.GetPubKey()
		require.NoError(t, err)

		hash := cmtrand.Bytes(tmhash.Size)
		proposal := &types.Proposal{
			Type:      cmtproto.ProposalType,
			Height:    1,
			Round:     2,
			POLRound:  2,
			BlockID:   types.BlockID{Hash: hash, PartSetHeader: types.PartSetHeader{Hash: hash, Total: 2}},
			Timestamp: time.Now(),
		}

		propPb := proposal.ToProto()
		require.NoError(t, tc.signerClient.SignProposal(tc.chainID, propPb))

		signBytes := types.ProposalSignBytes(tc.chainID, propPb)
		require.Len(t, propPb.Signature, hybrid.SignatureSize)
		require.True(t, pk.VerifySignature(signBytes, propPb.Signature))

		edHalf := ed25519.PubKey(pk.Bytes()[:ed25519.PubKeySize])
		require.False(t, edHalf.VerifySignature(signBytes, propPb.Signature))
	}
}
