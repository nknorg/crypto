package signature

import (
	"crypto/elliptic"
	"fmt"
	"math/big"
	"testing"
)

func TestCompress(t *testing.T) {
	kp, err := NewP256R1()
	fmt.Println(kp.pk, err)
	X := new(big.Int).SetBytes(kp.pk.(*P256R1PubKey).X)
	Y := new(big.Int).SetBytes(kp.pk.(*P256R1PubKey).Y)
	fmt.Println(X.Bytes(), Y)
	x_1 := elliptic.Marshal(elliptic.P256(), X, Y)
	fmt.Println(len(x_1))
}
