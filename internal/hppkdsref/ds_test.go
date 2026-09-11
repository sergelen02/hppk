package hppkdsref

import (
	"crypto"
	"math/big"
	"testing"
)

func toyParams() Parameters {
	return Parameters{Name: "toy", P: big.NewInt(13), N: 1, Lambda: 1, M: 1, L: 8, RBits: 32, Hash: crypto.SHA256}
}

func TestSignVerifyAndTamperRejection(t *testing.T) {
	p := toyParams()
	sk, pk, err := KeyGen(p)
	if err != nil { t.Fatal(err) }
	msg := []byte("hppk-ds test")
	sig, err := Sign(p, sk, msg)
	if err != nil { t.Fatal(err) }
	ok, err := Verify(pk, sig, msg)
	if err != nil { t.Fatal(err) }
	if !ok { t.Fatal("valid signature rejected") }
	ok, err = Verify(pk, sig, []byte("hppk-ds test!"))
	if err != nil { t.Fatal(err) }
	if ok { t.Fatal("tampered message accepted") }
}
