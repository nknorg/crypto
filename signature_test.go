package crypto

import (
	"encoding/hex"
	"testing"
)

func TestP256R1(t *testing.T) {
	msg := "77e74f1786b1f97c3b14100325201cc890906d0164d001b9210d4d28e217198a"

	kp, err := P256R1.New()
	if err != nil {
		t.Errorf("TestP256R1: New error: %v\n", err)
	}

	M, _ := hex.DecodeString(msg)
	RS, err := kp.PrivateKey().Sign(M)
	if err != nil {
		t.Errorf("TestP256R1: Sign error, %v\n", err)
	}

	if err := kp.PublicKey().Verify(M, RS); err != nil {
		t.Errorf("TestP256R1: verify error.\n")
	}

	M[1] = 0xFF
	if err := kp.PublicKey().Verify(M, RS); err == nil {
		t.Errorf("TestP256R1: verify error.\n")
	}
}

func TestEd25519(t *testing.T) {
	msg := "77e74f1786b1f97c3b14100325201cc890906d0164d001b9210d4d28e217198a"

	kp, err := ED25519.New()
	if err != nil {
		t.Errorf("TestEd25519: New error: %v\n", err)
	}

	M, _ := hex.DecodeString(msg)
	RS, err := kp.PrivateKey().Sign(M)
	if err != nil {
		t.Errorf("TestEd25519: Sign error, %v\n", err)
	}

	if err := kp.PublicKey().Verify(M, RS); err != nil {
		t.Errorf("TestEd25519: verify error.\n")
	}

	M[1] = 0xFF
	if err := kp.PublicKey().Verify(M, RS); err == nil {
		t.Errorf("TestEd25519: verify error.\n")
	}
}
