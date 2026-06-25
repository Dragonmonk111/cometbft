package hybrid

import (
	"bytes"
	"testing"

	"github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/crypto/mldsa44"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	priv := GenPrivKey()
	pub := priv.PubKey()
	msg := []byte("aegis phase F: hybrid consensus vote")

	sig, err := priv.Sign(msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if len(sig) != SignatureSize {
		t.Fatalf("sig len = %d, want %d", len(sig), SignatureSize)
	}
	if !pub.VerifySignature(msg, sig) {
		t.Fatal("valid hybrid signature rejected")
	}
	if pub.VerifySignature([]byte("different message"), sig) {
		t.Fatal("signature verified over wrong message")
	}
}

func TestPubKeySize(t *testing.T) {
	pub := GenPrivKey().PubKey()
	if len(pub.Bytes()) != PubKeySize {
		t.Fatalf("pubkey len = %d, want %d", len(pub.Bytes()), PubKeySize)
	}
	if PubKeySize != 1344 {
		t.Fatalf("PubKeySize = %d, want 1344", PubKeySize)
	}
	if SignatureSize != 2491 {
		t.Fatalf("SignatureSize = %d, want 2491", SignatureSize)
	}
}

// TestBothHalvesRequired is the core security property: tampering with EITHER
// half must fail verification.
func TestBothHalvesRequired(t *testing.T) {
	priv := GenPrivKey()
	pub := priv.PubKey()
	msg := []byte("both halves or nothing")
	sig, _ := priv.Sign(msg)

	// Corrupt the classical (ed25519) signature byte.
	classicalTamper := bytes.Clone(sig)
	classicalTamper[classicalHeaderLen]++ // first classical sig byte
	if pub.VerifySignature(msg, classicalTamper) {
		t.Fatal("verification passed with tampered classical half")
	}

	// Corrupt the PQC (ml-dsa-44) signature byte.
	pqcTamper := bytes.Clone(sig)
	pqcTamper[len(pqcTamper)-1]++ // last pqc sig byte
	if pub.VerifySignature(msg, pqcTamper) {
		t.Fatal("verification passed with tampered PQC half")
	}
}

// TestForgeryWithOneKey simulates one primitive being broken: an attacker who
// can forge ONLY the classical half (re-using a real PQC sig) must still fail.
func TestForgeryWithOneKey(t *testing.T) {
	victim := GenPrivKey()
	pub := victim.PubKey()
	msg := []byte("target")
	realSig, _ := victim.Sign(msg)
	_, realPQC, ok := decodeHybridSig(realSig)
	if !ok {
		t.Fatal("decode real sig")
	}

	// Attacker controls a DIFFERENT ed25519 key, pairs it with the victim's
	// real PQC signature. The classical half won't verify against victim's pub.
	forgedClassical, _ := ed25519.GenPrivKey().Sign(msg)
	forged := encodeHybridSig(forgedClassical, realPQC)
	if pub.VerifySignature(msg, forged) {
		t.Fatal("forgery with only classical key succeeded")
	}
}

// TestAddressInvariant: the hybrid address MUST equal the classical ed25519
// half's address (no validator-set migration, ADR-008 §F1-b).
func TestAddressInvariant(t *testing.T) {
	ed := ed25519.GenPrivKey()
	ml := mldsa44.GenPrivKey()
	hp, err := NewPrivKeyFromHalves(ed, ml)
	if err != nil {
		t.Fatalf("compose: %v", err)
	}
	hybridAddr := hp.PubKey().Address()
	classicalAddr := ed.PubKey().Address()
	if !bytes.Equal(hybridAddr, classicalAddr) {
		t.Fatalf("hybrid address %X != classical address %X", hybridAddr, classicalAddr)
	}
}

func TestFrameStrictness(t *testing.T) {
	priv := GenPrivKey()
	pub := priv.PubKey()
	msg := []byte("frame")
	sig, _ := priv.Sign(msg)

	// Wrong version byte.
	bad := bytes.Clone(sig)
	bad[0] = 0x02
	if pub.VerifySignature(msg, bad) {
		t.Fatal("accepted unknown version")
	}
	// Wrong total length.
	if pub.VerifySignature(msg, sig[:len(sig)-1]) {
		t.Fatal("accepted truncated signature")
	}
	// Wrong classical algo id.
	bad2 := bytes.Clone(sig)
	bad2[1] = 0x09
	if pub.VerifySignature(msg, bad2) {
		t.Fatal("accepted unknown classical algo id")
	}
}

// TestOldVerifierRejectsHybridSig: an un-upgraded (classical-only) node that
// receives a hybrid signature must NOT accidentally accept the first 64 bytes
// as a valid classical sig. The framing bytes prevent this. (ADR-008 §F3)
func TestOldVerifierRejectsHybridSig(t *testing.T) {
	hybridPriv := GenPrivKey()
	msg := []byte("vote from upgraded validator")
	hybridSig, _ := hybridPriv.Sign(msg)

	// A classical-only ed25519.PubKey — simulating a pre-migration validator.
	edPub, _ := hybridPriv.PubKey().(PubKey).halves()

	// The hybrid sig starts with framing bytes (version + algo_id + len), NOT
	// raw ed25519 signature bytes. A classical verifier sees an invalid sig.
	if edPub.VerifySignature(msg, hybridSig) {
		t.Fatal("classical-only verifier accepted a hybrid signature — F3 broken")
	}
}

func TestEqualsAndType(t *testing.T) {
	priv := GenPrivKey()
	if priv.Type() != KeyType {
		t.Fatalf("priv type = %q", priv.Type())
	}
	if !priv.Equals(priv) {
		t.Fatal("priv not equal to itself")
	}
	other := GenPrivKey()
	if priv.Equals(other) {
		t.Fatal("distinct privs reported equal")
	}
	if !priv.PubKey().Equals(priv.PubKey()) {
		t.Fatal("pub not equal to itself")
	}
}
