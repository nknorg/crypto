package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

var (
	data       = "2DBA419F26A216B9DA32B0A7C711A76509C7A879A765EF2613E2F5B3AADB45B2"
	SHA256R    = "703c56f2fa7c238e494bdf8d2fdd920cd2f8c835624f31b4f6eb3978d0d3a7ae"
	SHA3_256R  = "CDE6518934BB5066CD495F9C4A375671741FF3C7FD4D288CFD9F027D8922F6D8"
	RIPEMD160R = "FCFD26B00938A0124ECFF8C832F471E2ACE0F75D"
)

func TestSHA256(t *testing.T) {
	d, _ := hex.DecodeString(data)
	h := SHA256.Hash(d)
	r, _ := hex.DecodeString(SHA256R)
	if !bytes.Equal(h, r) {
		t.Errorf("SHA256: need: %v, but got: %v \n", r, h)
	}
}

func TestSHA3(t *testing.T) {
	d, _ := hex.DecodeString(data)
	h := SHA3_256.Hash(d)
	r, _ := hex.DecodeString(SHA3_256R)
	if !bytes.Equal(h, r) {
		t.Errorf("SHA3-256: need: %v, but got: %v \n", r, h)
	}
}

func TestRIPEMD160(t *testing.T) {
	d, _ := hex.DecodeString(data)
	h := RIPEMD160.Hash(d)
	r, _ := hex.DecodeString(RIPEMD160R)
	if !bytes.Equal(h, r) {
		t.Errorf("RIPEMD160: need: %v, but got: %v \n", r, h)
	}
}
