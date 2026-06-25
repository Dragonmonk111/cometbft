package mldsa44

import (
	"bytes"
	"testing"
)

func TestSignVerify(t *testing.T) {
	priv := GenPrivKey()
	pub := priv.PubKey()
	msg := []byte("ml-dsa-44 consensus vote")

	sig, err := priv.Sign(msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if len(sig) != SignatureSize {
		t.Fatalf("sig len = %d, want %d", len(sig), SignatureSize)
	}
	if !pub.VerifySignature(msg, sig) {
		t.Fatal("valid signature rejected")
	}
	if pub.VerifySignature([]byte("other"), sig) {
		t.Fatal("verified over wrong message")
	}
}

func TestDeterministicFromSeed(t *testing.T) {
	seed := bytes.Repeat([]byte{0x42}, SeedSize)
	a, err := GenPrivKeyFromSeed(seed)
	if err != nil {
		t.Fatalf("seed a: %v", err)
	}
	b, err := GenPrivKeyFromSeed(seed)
	if err != nil {
		t.Fatalf("seed b: %v", err)
	}
	if !bytes.Equal(a.PubKey().Bytes(), b.PubKey().Bytes()) {
		t.Fatal("same seed produced different public keys")
	}
}

func TestSizes(t *testing.T) {
	if PubKeySize != 1312 {
		t.Fatalf("PubKeySize = %d, want 1312", PubKeySize)
	}
	if SignatureSize != 2420 {
		t.Fatalf("SignatureSize = %d, want 2420", SignatureSize)
	}
	if SeedSize != 32 {
		t.Fatalf("SeedSize = %d, want 32", SeedSize)
	}
}

func TestTamperRejected(t *testing.T) {
	priv := GenPrivKey()
	pub := priv.PubKey()
	msg := []byte("tamper")
	sig, _ := priv.Sign(msg)
	sig[0]++
	if pub.VerifySignature(msg, sig) {
		t.Fatal("tampered signature accepted")
	}
}
