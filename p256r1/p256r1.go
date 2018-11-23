package p256r1

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	"github.com/nknorg/nkn/crypto/util"
)

func NewP256R1() (*Keypair, error) {
	privateKey := new(ecdsa.PrivateKey)
	if privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		return nil, errors.New("NewP256R1: Generate key pair error")
	}

	//TODO pk and sk alignment
	pk := &P256R1PubKey{
		X: privateKey.PublicKey.X.Bytes(),
		Y: privateKey.PublicKey.Y.Bytes(),
	}

	sk := &P256R1PrivKey{
		D: privateKey.D.Bytes(),
	}

	return &Keypair{
		pk: pk,
		sk: sk,
	}, nil
}

func (pk *P256R1PubKey) Verify(data []byte, signature []byte) error {
	len := len(signature)
	if len != util.SIGNATURELEN {
		return fmt.Errorf("Verify: Unknown signature length: %d\n", len)
	}

	r := new(big.Int).SetBytes(signature[:len/2])
	s := new(big.Int).SetBytes(signature[len/2:])

	digest := SHA256.Hash(data)

	pub := new(ecdsa.PublicKey)
	pub.Curve = elliptic.P256()

	pub.X = new(big.Int).SetBits(pk.X)
	pub.Y = new(big.Int).SetBits(pk.Y)

	if !ecdsa.Verify(pub, digest[:], r, s) {
		return errors.New("P256R1PubKey.Verify: failed.")
	}

	return nil
}

func (pk *P256R1PubKey) EqualTo(that PubKey) bool {
	return pk.Equal(that)
}

func (sk *P256R1PrivKey) Sign(data []byte) ([]byte, error) {
	digest := SHA256.Hash(data) // TODO  new func
	privateKey := &ecdsa.PrivateKey{
		Curve: elliptic.P256(),
		D:     new(big.Int).SetBytes(priKey),
	}

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest[:])
	if err != nil {
		return nil, fmt.Errorf("Sign: p256r1 sign error: %v\n", err)
	}

	signature := make([]byte, util.SIGNATURELEN)

	copy(signature[util.SIGNRLEN-r.Bytes():], r.Bytes())
	copy(signature[util.SIGNATURELEN-s.Bytes():], s.Bytes())

	return signature, nil
}
