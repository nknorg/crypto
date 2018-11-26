package crypto

import (
	"github.com/nknorg/crypto/signature"
)

type SIGALGO uint32

const (
	P256R1  SIGALGO = 1
	ED25519 SIGALGO = 2
)

var (
	sigAlgoes = make(map[SIGALGO]func() (*signature.Keypair, error), 0)
)

func (sig SIGALGO) New() (*signature.Keypair, error) {
	return sigAlgoes[sig]()
}

func init() {
	sigAlgoes[P256R1] = signature.NewP256R1
	sigAlgoes[ED25519] = signature.NewED25519
}
