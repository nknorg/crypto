package signature

const (
	HASHLEN       = 32
	PRIVATEKEYLEN = 32
	PUBLICKEYLEN  = 32
	SIGNRLEN      = 32
	SIGNSLEN      = 32
	SIGNATURELEN  = 64
)

type PubKey interface {
	EqualTo(pk PubKey) bool
	//VerifyAddress(addr string) error
	//ToAddress() string
	//Compress() //marshal
	//Decompress() //unmarshal
	Verify(data []byte, signature []byte) error
	Marshal() ([]byte, error)
	Unmarshal(data []byte) error
}

type PrivKey interface {
	PublicKey() PubKey
	Sign(data []byte) ([]byte, error)
	Marshal() ([]byte, error)
	Unmarshal(data []byte) error
}

type Keypair struct {
	pk PubKey
	sk PrivKey
}

func (kp *Keypair) PublicKey() PubKey {
	return kp.pk
}

func (kp *Keypair) PrivateKey() PrivKey {
	return kp.sk
}
