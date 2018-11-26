package signature

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
)

func NewP256R1() (*Keypair, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, errors.New("NewP256R1: Generate key pair error")
	}

	//TODO pk and sk alignment
	pk := P256R1PubKey{
		X: privateKey.PublicKey.X.Bytes(),
		Y: privateKey.PublicKey.Y.Bytes(),
	}

	sk := P256R1PrivKey{
		D: privateKey.D.Bytes(),
	}

	return &Keypair{
		pk: &pk,
		sk: &sk,
	}, nil
}

func (pk *P256R1PubKey) Verify(data []byte, signature []byte) error {
	len := len(signature)
	if len != SIGNATURELEN {
		return fmt.Errorf("Verify: Unknown signature length: %d\n", len)
	}

	r := new(big.Int).SetBytes(signature[:len/2])
	s := new(big.Int).SetBytes(signature[len/2:])

	digest := sha256.Sum256(data)

	pub := new(ecdsa.PublicKey)
	pub.Curve = elliptic.P256()

	pub.X = new(big.Int).SetBytes(pk.X)
	pub.Y = new(big.Int).SetBytes(pk.Y)

	if !ecdsa.Verify(pub, digest[:], r, s) {
		return errors.New("P256R1PubKey.Verify: failed.")
	}

	return nil
}

func (pk *P256R1PubKey) EqualTo(that PubKey) bool {
	return pk.Equal(that)
}

func (sk *P256R1PrivKey) Sign(data []byte) ([]byte, error) {
	digest := sha256.Sum256(data) // TODO  new func
	privateKey := &ecdsa.PrivateKey{
		D: new(big.Int).SetBytes(sk.D),
	}
	privateKey.Curve = elliptic.P256()

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest[:])
	if err != nil {
		return nil, fmt.Errorf("Sign: p256r1 sign error: %v\n", err)
	}

	signature := make([]byte, SIGNATURELEN)

	copy(signature[SIGNRLEN-len(r.Bytes()):], r.Bytes())
	copy(signature[SIGNATURELEN-len(s.Bytes()):], s.Bytes())

	return signature, nil
}

//func NewPubKey(priKey []byte) *PubKey {
//	privateKey := new(ecdsa.PrivateKey)
//	privateKey.PublicKey.Curve = algSet.Curve
//
//	k := new(big.Int)
//	k.SetBytes(priKey)
//	privateKey.D = k
//
//	privateKey.PublicKey.X, privateKey.PublicKey.Y = algSet.Curve.ScalarBaseMult(k.Bytes())
//
//	pubKey := new(PubKey)
//	pubKey.X = privateKey.PublicKey.X
//	pubKey.Y = privateKey.PublicKey.Y
//	return pubKey
//}
