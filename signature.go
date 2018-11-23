package crypto

type SIGALGO uint32

const (
	P256R1  SIGALGO = 1
	ED25519 SIGNLGO = 2
)

var (
	sigAlgoes = make(map[SIGALGO]func() Keypair, 0)
)

type PubKey interface {
	EqualTo(pk PubKey) bool
	//VerifyAddress(addr string) error
	//ToAddress() string
	Verify(data []byte, signature []byte) error
	Marshal() ([]byte, error)
	Unmarshal(data []byte) error
}

type PrivKey interface {
	//PubKey() PubKey
	Sign(data []byte) ([]byte, error)
	Marshal() ([]byte, error)
	Unmarshal(data []byte) error
}

type Keypair struct {
	pk PubKey
	sk PrivKey
}

func (sig SIGALGO) New() Keypair {
	return sigAlgoes[sig]()
}

func init() {
	sigAlgoes[P256R1] = NewP256R1
	sigAlgoes[ED25519] = NewED25519
}
