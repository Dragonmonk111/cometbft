package conn

// Project Aegis Phase C6 — hybrid-transport real-link RTT measurement.
//
// This measures the cost of the post-quantum-hybrid secret-connection handshake
// vs the classical one using the REAL fork code over REAL TCP sockets (not the
// in-memory pipe used by the functional tests). A symmetric one-way delay is
// injected on each Write to model link propagation, so the wall-clock numbers
// include the handshake's round trips at a given RTT.
//
// Run:  go test ./p2p/conn/ -run TestHybridHandshakeRTT -v
//
// It is informational (it asserts only that handshakes succeed); the numbers are
// emitted via t.Log and copied into aegis-transport/docs/PHASE_C6_RTT_RESULTS.md.

import (
	"net"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/libs/async"
)

// delayCountConn wraps a net.Conn to (a) inject a one-way propagation delay on
// each Write and (b) count bytes written, so we can report both handshake
// wall-clock time and bytes-on-wire.
type delayCountConn struct {
	net.Conn
	oneWay  time.Duration
	written *int64
}

func (c *delayCountConn) Write(p []byte) (int, error) {
	if c.oneWay > 0 {
		time.Sleep(c.oneWay)
	}
	n, err := c.Conn.Write(p)
	atomic.AddInt64(c.written, int64(n))
	return n, err
}

// establishOnce sets up one real TCP socket pair, runs both handshakes
// concurrently with the given one-way delay, and returns the wall-clock time to
// establish both ends plus the total bytes written across both peers.
func establishOnce(tb testing.TB, hybrid bool, oneWay time.Duration) (time.Duration, int64) {
	tb.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(tb, err)
	defer ln.Close()

	var srvConn net.Conn
	var srvErr error
	accepted := make(chan struct{})
	go func() {
		srvConn, srvErr = ln.Accept()
		close(accepted)
	}()

	cliConn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(tb, err)
	<-accepted
	require.NoError(tb, srvErr)

	var cliTx, srvTx int64
	cli := &delayCountConn{Conn: cliConn, oneWay: oneWay, written: &cliTx}
	srv := &delayCountConn{Conn: srvConn, oneWay: oneWay, written: &srvTx}
	defer cli.Close()
	defer srv.Close()

	cliKey := ed25519.GenPrivKey()
	srvKey := ed25519.GenPrivKey()

	start := time.Now()
	trs, _ := async.Parallel(
		func(_ int) (interface{}, bool, error) {
			var e error
			if hybrid {
				_, e = MakeSecretConnectionHybrid(cli, cliKey)
			} else {
				_, e = MakeSecretConnection(cli, cliKey)
			}
			return nil, e != nil, e
		},
		func(_ int) (interface{}, bool, error) {
			var e error
			if hybrid {
				_, e = MakeSecretConnectionHybrid(srv, srvKey)
			} else {
				_, e = MakeSecretConnection(srv, srvKey)
			}
			return nil, e != nil, e
		},
	)
	dur := time.Since(start)
	require.Nil(tb, trs.FirstError())
	return dur, cliTx + srvTx
}

func medianHandshake(tb testing.TB, hybrid bool, oneWay time.Duration, n int) time.Duration {
	tb.Helper()
	ds := make([]time.Duration, 0, n)
	for i := 0; i < n; i++ {
		d, _ := establishOnce(tb, hybrid, oneWay)
		ds = append(ds, d)
	}
	sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
	return ds[n/2]
}

func TestHybridHandshakeRTT(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping RTT measurement in -short mode")
	}

	const n = 9
	rtts := []time.Duration{0, 10 * time.Millisecond, 50 * time.Millisecond}

	t.Logf("ADR-006 hybrid secret-connection handshake over real TCP (median of %d):", n)
	t.Logf("  %-10s | %-14s | %-14s | %-12s", "link RTT", "classical", "hybrid", "delta")
	t.Logf("  %-10s-+-%-14s-+-%-14s-+-%-12s", "----------", "--------------", "--------------", "------------")
	for _, rtt := range rtts {
		oneWay := rtt / 2
		c := medianHandshake(t, false, oneWay, n)
		h := medianHandshake(t, true, oneWay, n)
		t.Logf("  %-10s | %-14s | %-14s | +%-11s",
			rtt, c.Round(time.Microsecond), h.Round(time.Microsecond), (h - c).Round(time.Microsecond))
	}

	// Bytes-on-wire are latency-independent; measure once at zero delay.
	_, cTx := establishOnce(t, false, 0)
	_, hTx := establishOnce(t, true, 0)
	t.Logf("bytes on wire (both peers, full handshake): classical=%d  hybrid=%d  (delta +%d)", cTx, hTx, hTx-cTx)
}
