package conn

// Project Aegis Phase C — post-quantum-hybrid secret connection.
//
// This file is an ADDITIVE drop-in alongside the classical secret_connection.go.
// It implements the ADR-006 hybrid handshake: session keys are derived from BOTH
// a classical X25519 ECDH secret AND an ML-KEM-768 (FIPS 203) shared secret, so
// the link stays confidential unless an attacker breaks BOTH primitives.
//
// Everything downstream of key derivation — ChaCha20-Poly1305 framing, the STS
// challenge authentication, nonce handling — is the SAME as the classical path;
// only the key-agreement input changes. The classical secret_connection.go and
// its golden/adversarial tests are left untouched.

import (
	"bytes"
	"crypto/mlkem"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	gogotypes "github.com/cosmos/gogoproto/types"
	"github.com/oasisprotocol/curve25519-voi/primitives/merlin"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/libs/async"
	"github.com/cometbft/cometbft/libs/protoio"
)

// ML-KEM-768 (FIPS 203) wire sizes.
const (
	mlkem768EncapKeySize   = 1184
	mlkem768CiphertextSize = 1088

	labelMLKEMLowerEncapKey = "MLKEM768_LOWER_ENCAP_KEY"
	labelMLKEMUpperEncapKey = "MLKEM768_UPPER_ENCAP_KEY"
	labelMLKEMCiphertext    = "MLKEM768_CIPHERTEXT"
)

// MakeSecretConnectionHybrid performs the ADR-006 hybrid (X25519 + ML-KEM-768)
// handshake and returns an authenticated SecretConnection. It is wire-compatible
// in everything except the key-agreement phase, so two hybrid peers interoperate
// but a hybrid peer cannot talk to a classical peer (negotiation/fallback is a
// separate, higher-layer concern — see aegis-transport/secretconn/PORTING.md §4).
func MakeSecretConnectionHybrid(conn io.ReadWriteCloser, locPrivKey crypto.PrivKey) (*SecretConnection, error) {
	locPubKey := locPrivKey.PubKey()

	// (1) Classical ephemeral X25519 keypair (reuses the classical generator).
	locEphPub, locEphPriv := genEphKeys()

	// (1b) Post-quantum ephemeral ML-KEM-768 keypair.
	mlkemDK, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, fmt.Errorf("aegis: ml-kem-768 keygen: %w", err)
	}
	locEk := mlkemDK.EncapsulationKey().Bytes()

	// (2) Exchange {X25519 ephemeral pubkey || ML-KEM encapsulation key}.
	remEphPub, remEk, err := shareEphHybrid(conn, locEphPub, locEk)
	if err != nil {
		return nil, err
	}

	// Sort by lexical order of the X25519 pubkeys (the existing rule). This also
	// assigns the asymmetric ML-KEM role: lo = initiator (decapsulates),
	// hi = responder (encapsulates and sends the single ciphertext).
	loEphPub, hiEphPub := sort32(locEphPub, remEphPub)
	locIsLeast := bytes.Equal(locEphPub[:], loEphPub[:])

	transcript := merlin.NewTranscript("TENDERMINT_SECRET_CONNECTION_TRANSCRIPT_HASH")
	transcript.AppendMessage(labelEphemeralLowerPublicKey, loEphPub[:])
	transcript.AppendMessage(labelEphemeralUpperPublicKey, hiEphPub[:])

	// Bind both ML-KEM encapsulation keys into the transcript in the same sorted
	// order — any tamper/downgrade of the PQ material breaks the challenge MAC.
	var loEk, hiEk []byte
	if locIsLeast {
		loEk, hiEk = locEk, remEk
	} else {
		loEk, hiEk = remEk, locEk
	}
	transcript.AppendMessage(labelMLKEMLowerEncapKey, loEk)
	transcript.AppendMessage(labelMLKEMUpperEncapKey, hiEk)

	// (3) Classical X25519 shared secret.
	dhSecret, err := computeDHSecret(remEphPub, locEphPriv)
	if err != nil {
		return nil, err
	}
	transcript.AppendMessage(labelDHSecret, dhSecret[:])

	// (4) ML-KEM-768 encapsulation/decapsulation: a single ciphertext, hi -> lo.
	var ssPQ, ciphertext []byte
	if locIsLeast {
		// lo = initiator: receive the ciphertext and decapsulate with our key.
		ciphertext, err = recvKEMCiphertext(conn)
		if err != nil {
			return nil, err
		}
		ssPQ, err = mlkemDK.Decapsulate(ciphertext)
		if err != nil {
			return nil, fmt.Errorf("aegis: ml-kem-768 decapsulate: %w", err)
		}
	} else {
		// hi = responder: encapsulate against lo's encapsulation key, send ct.
		remEncapKey, kerr := mlkem.NewEncapsulationKey768(remEk)
		if kerr != nil {
			return nil, fmt.Errorf("aegis: ml-kem-768 bad remote encap key: %w", kerr)
		}
		ssPQ, ciphertext = remEncapKey.Encapsulate()
		if err = sendKEMCiphertext(conn, ciphertext); err != nil {
			return nil, err
		}
	}
	transcript.AppendMessage(labelMLKEMCiphertext, ciphertext)

	// (5) Fold classical + PQ secrets into one 32-byte secret, then run the
	// EXISTING key derivation. combineHybridSecrets keeps deriveSecrets a pure
	// function of a 32-byte input, so the classical golden vectors are unchanged;
	// recovering the AEAD keys requires BOTH X25519 and ML-KEM-768.
	combinedSecret := combineHybridSecrets(dhSecret, ssPQ)
	recvSecret, sendSecret := deriveSecrets(combinedSecret, locIsLeast)

	const challengeSize = 32
	var challenge [challengeSize]byte
	transcript.ExtractBytes(challenge[:], labelSecretConnectionMac)

	sendAead, err := chacha20poly1305.New(sendSecret[:])
	if err != nil {
		return nil, errors.New("invalid send SecretConnection Key")
	}
	recvAead, err := chacha20poly1305.New(recvSecret[:])
	if err != nil {
		return nil, errors.New("invalid receive SecretConnection Key")
	}

	sc := &SecretConnection{
		conn:            conn,
		recvBuffer:      nil,
		recvNonce:       new([aeadNonceSize]byte),
		sendNonce:       new([aeadNonceSize]byte),
		recvAead:        recvAead,
		sendAead:        sendAead,
		recvFrame:       make([]byte, totalFrameSize),
		recvSealedFrame: make([]byte, aeadSizeOverhead+totalFrameSize),
		sendFrame:       make([]byte, totalFrameSize),
		sendSealedFrame: make([]byte, aeadSizeOverhead+totalFrameSize),
	}

	// (6) STS mutual authentication over the now-encrypted channel (unchanged).
	locSignature, err := signChallenge(&challenge, locPrivKey)
	if err != nil {
		return nil, err
	}
	authSigMsg, err := shareAuthSignature(sc, locPubKey, locSignature)
	if err != nil {
		return nil, err
	}
	remPubKey, remSignature := authSigMsg.Key, authSigMsg.Sig
	if _, ok := remPubKey.(ed25519.PubKey); !ok {
		return nil, fmt.Errorf("expected ed25519 pubkey, got %T", remPubKey)
	}
	if !remPubKey.VerifySignature(challenge[:], remSignature) {
		return nil, errors.New("challenge verification failed")
	}

	sc.remPubKey = remPubKey
	return sc, nil
}

// combineHybridSecrets folds the classical and post-quantum shared secrets into a
// single 32-byte secret. SHA-256(dh || pq) depends on both inputs, so the derived
// AEAD keys remain secure unless BOTH X25519 and ML-KEM-768 are broken.
func combineHybridSecrets(dhSecret *[32]byte, ssPQ []byte) *[32]byte {
	h := sha256.New()
	h.Write(dhSecret[:])
	h.Write(ssPQ)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return &out
}

// shareEphHybrid exchanges {X25519 ephemeral pubkey || ML-KEM-768 encap key} as a
// single framed message, mirroring shareEphPubKey's parallel send/receive so it
// cannot deadlock on a duplex stream.
func shareEphHybrid(conn io.ReadWriter, locEphPub *[32]byte, locEk []byte) (remEphPub *[32]byte, remEk []byte, err error) {
	msg := make([]byte, 0, 32+len(locEk))
	msg = append(msg, locEphPub[:]...)
	msg = append(msg, locEk...)

	trs, _ := async.Parallel(
		func(_ int) (val interface{}, abort bool, err error) {
			_, err = protoio.NewDelimitedWriter(conn).WriteMsg(&gogotypes.BytesValue{Value: msg})
			if err != nil {
				return nil, true, err
			}
			return nil, false, nil
		},
		func(_ int) (val interface{}, abort bool, err error) {
			var bz gogotypes.BytesValue
			_, err = protoio.NewDelimitedReader(conn, 1024*1024).ReadMsg(&bz)
			if err != nil {
				return nil, true, err
			}
			return bz.Value, false, nil
		},
	)
	if trs.FirstError() != nil {
		return nil, nil, trs.FirstError()
	}

	remote, ok := trs.FirstValue().([]byte)
	if !ok {
		return nil, nil, errors.New("aegis: hybrid eph exchange returned no value")
	}
	if len(remote) != 32+mlkem768EncapKeySize {
		return nil, nil, fmt.Errorf("aegis: bad hybrid eph message: got %d bytes, want %d", len(remote), 32+mlkem768EncapKeySize)
	}
	var rep [32]byte
	copy(rep[:], remote[:32])
	ek := make([]byte, mlkem768EncapKeySize)
	copy(ek, remote[32:])
	return &rep, ek, nil
}

// sendKEMCiphertext writes the single ML-KEM-768 ciphertext frame (responder -> initiator).
func sendKEMCiphertext(conn io.Writer, ct []byte) error {
	_, err := protoio.NewDelimitedWriter(conn).WriteMsg(&gogotypes.BytesValue{Value: ct})
	return err
}

// recvKEMCiphertext reads and length-checks the single ML-KEM-768 ciphertext frame.
func recvKEMCiphertext(conn io.Reader) ([]byte, error) {
	var bz gogotypes.BytesValue
	if _, err := protoio.NewDelimitedReader(conn, 1024*1024).ReadMsg(&bz); err != nil {
		return nil, err
	}
	if len(bz.Value) != mlkem768CiphertextSize {
		return nil, fmt.Errorf("aegis: bad ml-kem-768 ciphertext: got %d bytes, want %d", len(bz.Value), mlkem768CiphertextSize)
	}
	return bz.Value, nil
}
