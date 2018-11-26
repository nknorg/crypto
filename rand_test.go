package crypto

import (
	"bytes"
	"testing"
)

func TestRand(t *testing.T) {
	r1 := make([]byte, 8)
	r2 := make([]byte, 8)
	l1, e1 := RandBytes(r1)
	l2, e2 := RandBytes(r2)
	if e1 != nil || e2 != nil {
		t.Errorf("TestRand: generate random number error, err1=%v, err2=%v\n", e1, e2)
	}

	if l1 != 8 || l2 != 8 {
		t.Errorf("TestRand: generate random number error,len(r1)=%v, len(r2)=%v", l1, l2)
	}

	if bytes.Equal(r1, r2) {
		t.Errorf("TestRand: generate random number error,r1=%v, r2=%v", r1, r2)
	}
}
