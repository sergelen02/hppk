package hppkkemref

import (
	"math/big"
	"testing"
)

func TestKeyGenAlgorithm1Invariants(t *testing.T) {
	p := Parameters{Name: "toy-kem", P: big.NewInt(13), N: 1, Lambda: 1, M: 2}
	sk, pk, err := KeyGen(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(sk.F) != 2 || len(sk.H) != 2 {
		t.Fatal("secret polynomial degree does not match lambda")
	}
	if len(pk.P) != 3 || len(pk.Q) != 3 || len(pk.P[0]) != 2 {
		t.Fatal("public matrix shape does not match n+lambda+1 by m")
	}
	if new(big.Int).GCD(nil, nil, sk.R1, sk.S1).Cmp(big.NewInt(1)) != 0 ||
		new(big.Int).GCD(nil, nil, sk.R2, sk.S2).Cmp(big.NewInt(1)) != 0 {
		t.Fatal("hidden-ring multiplier is not invertible")
	}
	for i := range pk.P {
		for j := range pk.P[i] {
			if pk.P[i][j].Sign() < 0 || pk.P[i][j].Cmp(sk.S1) >= 0 ||
				pk.Q[i][j].Sign() < 0 || pk.Q[i][j].Cmp(sk.S2) >= 0 {
				t.Fatal("encrypted public coefficient outside its hidden ring")
			}
		}
	}
}
