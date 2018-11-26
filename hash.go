package crypto

import (
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/sha3"
)

type HASH uint32

const (
	SHA256    HASH = 1
	SHA3_256  HASH = 2
	RIPEMD160 HASH = 3
)

const (
	HASH256_LEN = 32
	HASH160_LEN = 20
)

type hashInst struct {
	hashfunc func(data []byte) []byte
	size     int
	name     string
}

var hashes = make(map[HASH]hashInst, 0)

func (h HASH) Hash(value []byte) []byte {
	return hashes[h].hashfunc(value)
}

func (h HASH) Size() int {
	return hashes[h].size
}

func (h HASH) Name() string {
	return hashes[h].name
}

func sha256_inner(value []byte) []byte {
	data := make([]byte, HASH256_LEN)
	digest := sha256.Sum256(value)
	copy(data, digest[0:HASH256_LEN])

	return data
}

func sha3_256_inner(value []byte) []byte {
	data := make([]byte, HASH256_LEN)
	digest := sha3.Sum256(value)
	copy(data, digest[0:HASH256_LEN])

	return data
}

func ripemd160_inner(value []byte) []byte {
	md := ripemd160.New()
	io.WriteString(md, string(value))
	hash := md.Sum(nil)

	return hash
}

func init() {
	hashes[SHA256] = hashInst{sha256_inner, HASH256_LEN, "SHA256"}
	hashes[SHA3_256] = hashInst{sha3_256_inner, HASH256_LEN, "SHA3_256"}
	hashes[RIPEMD160] = hashInst{ripemd160_inner, HASH160_LEN, "RIPEMD160"}
}
