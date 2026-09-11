package hppkdsref

import (
	"crypto"
	"math/big"
	"testing"
)

func TestReferenceParameterInvariant(t *testing.T) {
	p := Parameters{Name: "toy", P: big.NewInt(13), N: 1, Lambda: 1, M: 1, L: 8, RBits: 12, Hash: crypto.SHA256}
	if err := p.Validate(); err != nil { t.Fatal(err) }
	p.M = 2
	if err := p.Validate(); err == nil { t.Fatal("expected rejection for a non-reference dimension") }
}
