package conn

import (
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/libs/async"
)

// makeHybridSecretConnPair establishes a hybrid (X25519 + ML-KEM-768) secret
// connection on both ends of a pipe and asserts each side authenticated the
// other's ed25519 pubkey.
func makeHybridSecretConnPair(tb testing.TB) (fooSecConn, barSecConn *SecretConnection) {
	tb.Helper()
	var (
		fooConn, barConn = makeKVStoreConnPair()
		fooPrvKey        = ed25519.GenPrivKey()
		fooPubKey        = fooPrvKey.PubKey()
		barPrvKey        = ed25519.GenPrivKey()
		barPubKey        = barPrvKey.PubKey()
	)

	trs, ok := async.Parallel(
		func(_ int) (val interface{}, abort bool, err error) {
			fooSecConn, err = MakeSecretConnectionHybrid(fooConn, fooPrvKey)
			if err != nil {
				tb.Errorf("failed to establish hybrid SecretConnection for foo: %v", err)
				return nil, true, err
			}
			if !fooSecConn.RemotePubKey().Equals(barPubKey) {
				err = fmt.Errorf("unexpected foo remote pubkey")
				tb.Error(err)
				return nil, true, err
			}
			return nil, false, nil
		},
		func(_ int) (val interface{}, abort bool, err error) {
			barSecConn, err = MakeSecretConnectionHybrid(barConn, barPrvKey)
			if err != nil {
				tb.Errorf("failed to establish hybrid SecretConnection for bar: %v", err)
				return nil, true, err
			}
			if !barSecConn.RemotePubKey().Equals(fooPubKey) {
				err = fmt.Errorf("unexpected bar remote pubkey")
				tb.Error(err)
				return nil, true, err
			}
			return nil, false, nil
		},
	)

	require.Nil(tb, trs.FirstError())
	require.True(tb, ok, "unexpected task abortion")
	return fooSecConn, barSecConn
}

// TestHybridSecretConnectionHandshake proves two hybrid peers agree and mutually
// authenticate over the X25519 + ML-KEM-768 handshake.
func TestHybridSecretConnectionHandshake(t *testing.T) {
	fooSecConn, barSecConn := makeHybridSecretConnPair(t)
	require.NoError(t, fooSecConn.Close())
	require.NoError(t, barSecConn.Close())
}

// TestHybridSecretConnectionReadWrite proves the post-handshake AEAD channel
// carries data correctly in both directions.
func TestHybridSecretConnectionReadWrite(t *testing.T) {
	fooSecConn, barSecConn := makeHybridSecretConnPair(t)

	// foo -> bar
	fooMsg := []byte("post-quantum hybrid handshake: foo to bar")
	done := make(chan struct{})
	go func() {
		_, werr := fooSecConn.Write(fooMsg)
		assert.NoError(t, werr)
		close(done)
	}()
	fooBuf := make([]byte, len(fooMsg))
	_, err := io.ReadFull(barSecConn, fooBuf)
	require.NoError(t, err)
	require.Equal(t, fooMsg, fooBuf)
	<-done

	// bar -> foo
	barMsg := []byte("post-quantum hybrid handshake: bar to foo")
	done2 := make(chan struct{})
	go func() {
		_, werr := barSecConn.Write(barMsg)
		assert.NoError(t, werr)
		close(done2)
	}()
	barBuf := make([]byte, len(barMsg))
	_, err = io.ReadFull(fooSecConn, barBuf)
	require.NoError(t, err)
	require.Equal(t, barMsg, barBuf)
	<-done2

	require.NoError(t, fooSecConn.Close())
	require.NoError(t, barSecConn.Close())
}

// TestHybridCombineSecretsBindsBoth proves the KEM combiner depends on BOTH the
// classical and the post-quantum secret: changing either changes the output, so
// neither half alone determines the session keys.
func TestHybridCombineSecretsBindsBoth(t *testing.T) {
	var dh [32]byte
	for i := range dh {
		dh[i] = byte(i)
	}
	pq := make([]byte, 32)
	for i := range pq {
		pq[i] = byte(255 - i)
	}

	base := combineHybridSecrets(&dh, pq)

	// Flip one bit of the classical secret.
	dh2 := dh
	dh2[0] ^= 0x01
	require.NotEqual(t, base, combineHybridSecrets(&dh2, pq), "combiner ignored the classical secret")

	// Flip one bit of the PQ secret.
	pq2 := make([]byte, len(pq))
	copy(pq2, pq)
	pq2[0] ^= 0x01
	require.NotEqual(t, base, combineHybridSecrets(&dh, pq2), "combiner ignored the PQ secret")
}
