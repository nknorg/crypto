package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"

	. "github.com/nknorg/nkn/common"
)

func ToAesKey(pwd []byte) []byte {
	return SHA256.Hash(SHA256.Hash(pwd))
}

func AesEncrypt(plaintext []byte, key []byte, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("AesEncrypt: Invalid key. %v\n", err)
	}

	if len(plaintext) % block.BlockSize() {
		return nil, errors.New("AesEncrypt: input not full blocks.")
	}
	ciphertext := make([]byte, len(plaintext))

	blockMode := cipher.NewCBCEncrypter(block, iv)
	blockMode.CryptBlocks(ciphertext, plaintext)

	return ciphertext, nil
}

func AesDecrypt(ciphertext []byte, key []byte, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("AesDecrypt: invalid key. %v\n", err)
	}

	if len(plaintext) % block.BlockSize() {
		return nil, errors.New("AesDecrypt: input not full blocks.")
	}
	plaintext := make([]byte, len(ciphertext))

	blockModel := cipher.NewCBCDecrypter(block, iv)
	blockModel.CryptBlocks(plaintext, ciphertext)

	return plaintext, nil
}
