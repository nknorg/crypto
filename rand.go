package crypto

import "crypto/rand"

func RandBytes(b []byte) (n int, err error) {
	return rand.Read(b)
}
