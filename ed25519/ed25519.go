package types

import (
	"crypto/rand"
	"errors"

	"github.com/agl/ed25519"
)

func NewEd25519() (*Keypair, error) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, errors.New("NewEd25519: Generate key pair error")
	}

	return &Keypair{
		pk: pk,
		sk: sk,
	}, nil

}

func (pk *ED25519PubKey) Verify(data []byte, signature []byte) error {
	if !ed25519.Verify(pk.PK, data, signature) {
		return error.New("ED25519PubKey.Verify: failed.")
	}

	return nil
}

func (pk *ED25519PubKey) EqualTo(that PubKey) bool {
	return pk.Equal(that)
}

func (sk *ED25519PrivKey) Sign(data []byte) ([]byte, error) {
	return ed25519.Sign(sk.SK, data), nil
}
