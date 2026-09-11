package hppkdsref

import (
	"fmt"
	"math/big"
)

func eval(coeff []*big.Int, x, p *big.Int) *big.Int {
	acc, power := new(big.Int), big.NewInt(1)
	for _, c := range coeff {
		acc.Add(acc, new(big.Int).Mul(c, power))
		acc.Mod(acc, p)
		power.Mul(power, x)
		power.Mod(power, p)
	}
	return acc
}

// Sign implements Algorithm 5. F carries f(x) in Z/S2Z and H carries h(x)
// in Z/S1Z, so Algorithm 6 checks H*P(x)=F*Q(x).
func Sign(p Parameters, sk *SecretKey, message []byte) (*Signature, error) {
	if sk == nil || len(sk.F) != int(p.Lambda+1) || len(sk.H) != int(p.Lambda+1) {
		return nil, fmt.Errorf("invalid secret key")
	}
	x, err := HashToField(p, message)
	if err != nil { return nil, err }
	fv, hv := eval(sk.F, x, p.P), eval(sk.H, x, p.P)
	r1Inv := new(big.Int).ModInverse(sk.R1, sk.S1)
	r2Inv := new(big.Int).ModInverse(sk.R2, sk.S2)
	if r1Inv == nil || r2Inv == nil { return nil, fmt.Errorf("non-invertible hidden ring multiplier") }
	return &Signature{
		F: new(big.Int).Mod(new(big.Int).Mul(r2Inv, fv), sk.S2),
		H: new(big.Int).Mod(new(big.Int).Mul(r1Inv, hv), sk.S1),
	}, nil
}
