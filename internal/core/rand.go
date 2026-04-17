package core

import (
	"crypto/rand"
	"math/big"
)

func RandMod(p *big.Int) *big.Int {
	z, err := rand.Int(rand.Reader, p)
	if err != nil {
		panic(err)
	}
	return z
}

func RandBits(bits uint) *big.Int {
	if bits == 0 {
		return big.NewInt(0)
	}
	limit := new(big.Int).Lsh(big.NewInt(1), bits)
	z, err := rand.Int(rand.Reader, limit)
	if err != nil {
		panic(err)
	}
	if z.Sign() == 0 {
		return big.NewInt(1)
	}
	return z
}

func RandCoprime(modulus *big.Int, bits uint) *big.Int {
	one := big.NewInt(1)
	for {
		r := new(big.Int).Mod(RandBits(bits), modulus)
		if r.Sign() == 0 {
			continue
		}
		if new(big.Int).GCD(nil, nil, r, modulus).Cmp(one) == 0 {
			return r
		}
	}
}
