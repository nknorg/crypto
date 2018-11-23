package crypto

type SIGALGO uint32

const (
	P256R1  SIGALGO = 1
	ED25519 SIGNLGO = 2
)

var (
	sigAlgoes = make(map[SIGALGO]func() signature.Keypair, 0)
)

func (sig SIGALGO) New() *signature.Keypair {
	return sigAlgoes[sig]()
}

func init() {
	sigAlgoes[P256R1] = signature.NewP256R1
	sigAlgoes[ED25519] = signature.NewED25519
}
