package hppkdsref

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

func sampleMod(mod *big.Int) (*big.Int, error) {
	return rand.Int(rand.Reader, mod)
}

func sampleNonZeroMod(mod *big.Int) (*big.Int, error) {
	for {
		x, err := sampleMod(mod)
		if err != nil || x.Sign() != 0 {
			return x, err
		}
	}
}

func sampleOdd(bits uint) (*big.Int, error) {
	if bits < 3 {
		return nil, fmt.Errorf("ring bit length must be at least 3")
	}
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), bits-1))
	if err != nil { return nil, err }
	n.SetBit(n, int(bits-1), 1)
	n.SetBit(n, 0, 1)
	return n, nil
}

func hiddenRing(bits uint) (r, s *big.Int, err error) {
	s, err = sampleOdd(bits)
	if err != nil { return nil, nil, err }
	for {
		r, err = sampleMod(s)
		if err != nil { return nil, nil, err }
		if r.Sign() != 0 && new(big.Int).GCD(nil, nil, r, s).Cmp(big.NewInt(1)) == 0 {
			return r, s, nil
		}
	}
}

func matrix(rows, cols int) [][]*big.Int {
	z := make([][]*big.Int, rows)
	for i := range z {
		z[i] = make([]*big.Int, cols)
		for j := range z[i] { z[i][j] = new(big.Int) }
	}
	return z
}

// KeyGen implements Algorithm 4. The convolution includes both endpoints:
// sum_{s=0}^{i} f_s c_{i-s,j}. This is the standard product coefficient.
func KeyGen(p Parameters) (*SecretKey, *PublicKey, error) {
	if err := p.Validate(); err != nil { return nil, nil, err }
	deg, cols := int(p.N+p.Lambda), int(p.M)
	f, h := make([]*big.Int, p.Lambda+1), make([]*big.Int, p.Lambda+1)
	c := matrix(int(p.N)+1, cols)
	var err error
	for i := range f {
		if f[i], err = sampleMod(p.P); err != nil { return nil, nil, err }
		if h[i], err = sampleMod(p.P); err != nil { return nil, nil, err }
	}
	for i := range c {
		for j := range c[i] {
			if c[i][j], err = sampleMod(p.P); err != nil { return nil, nil, err }
		}
	}
	r1, s1, err := hiddenRing(2*uint(p.P.BitLen()) + 16)
	if err != nil { return nil, nil, err }
	r2, s2, err := hiddenRing(2*uint(p.P.BitLen()) + 16)
	if err != nil { return nil, nil, err }
	// beta=0 makes every transformed public coefficient zero and must be rejected.
	beta, err := sampleNonZeroMod(p.P)
	if err != nil { return nil, nil, err }

	pp, qp, mu, nu := matrix(deg+1, cols), matrix(deg+1, cols), matrix(deg+1, cols), matrix(deg+1, cols)
	R := new(big.Int).Lsh(big.NewInt(1), p.RBits)
	for i := 0; i <= deg; i++ {
		for j := 0; j < cols; j++ {
			rawP, rawQ := new(big.Int), new(big.Int)
			for s := 0; s <= i; s++ {
				if s < len(f) && i-s < len(c) {
					rawP.Add(rawP, new(big.Int).Mul(f[s], c[i-s][j]))
					rawQ.Add(rawQ, new(big.Int).Mul(h[s], c[i-s][j]))
				}
			}
			rawP.Mod(rawP, p.P); rawQ.Mod(rawQ, p.P)
			barP := new(big.Int).Mod(new(big.Int).Mul(r1, rawP), s1)
			barQ := new(big.Int).Mod(new(big.Int).Mul(r2, rawQ), s2)
			pp[i][j].Mod(new(big.Int).Mul(beta, barP), p.P)
			qp[i][j].Mod(new(big.Int).Mul(beta, barQ), p.P)
			mu[i][j].Quo(new(big.Int).Mul(barP, R), s1)
			nu[i][j].Quo(new(big.Int).Mul(barQ, R), s2)
		}
	}
	return &SecretKey{F: f, H: h, R1: r1, S1: s1, R2: r2, S2: s2},
		&PublicKey{Params: p, PPrime: pp, QPrime: qp, Mu: mu, Nu: nu,
			S1: new(big.Int).Mod(new(big.Int).Mul(beta, s1), p.P),
			S2: new(big.Int).Mod(new(big.Int).Mul(beta, s2), p.P)}, nil
}
