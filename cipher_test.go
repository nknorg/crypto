package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

var (
	password = []byte{1, 2, 3, 4, 5, 6}
	IV       = "000102030405060708090a0b0c0d0e0f"
	M        = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
	C        = "77e74f1786b1f97c3b14100325201cc890906d0164d001b9210d4d28e217198a"
)

func TestAes(t *testing.T) {
	key := ToAesKey(password)

	in, _ := hex.DecodeString(M)
	iv, _ := hex.DecodeString(IV)
	out, _ := hex.DecodeString(C)

	c, err := AesEncrypt(in, key, iv)
	if err != nil || !bytes.Equal(c, out) {
		t.Errorf("TesAes: AesEncrypt error: %v", err)
	}

	m, err := AesDecrypt(c, key, iv)
	if err != nil || !bytes.Equal(m, in) {
		t.Errorf("TesAes: AesDecrypt error: %v", err)
	}
}
