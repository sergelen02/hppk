package hppkkemref

import (
	"crypto/rand"
	"math/big"
)

func sampleMod(mod *big.Int) (*big.Int, error) {
	return rand.Int(rand.Reader, mod)
}

func sampleOdd(bits uint) (*big.Int, error) {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), bits-1))
	if err != nil {
		return nil, err
	}
	n.SetBit(n, int(bits-1), 1)
	n.SetBit(n, 0, 1)
	return n, nil
}

func hiddenRing(bits uint) (r, s *big.Int, err error) {
	s, err = sampleOdd(bits)
	if err != nil {
		return nil, nil, err
	}
	for {
		r, err = sampleMod(s)
		if err != nil {
			return nil, nil, err
		}
		if r.Sign() != 0 && new(big.Int).GCD(nil, nil, r, s).Cmp(big.NewInt(1)) == 0 {
			return r, s, nil
		}
	}
}

func matrix(rows, cols int) [][]*big.Int {
	out := make([][]*big.Int, rows)
	for i := range out {
		out[i] = make([]*big.Int, cols)
		for j := range out[i] {
			out[i][j] = new(big.Int)
		}
	}
	return out
}

// KeyGen implements Algorithm 1. It generates f,h,beta; computes the
// convolution coefficients of P=f*beta and Q=h*beta over F_p; then hides
// them using two independent co-prime hidden-ring multipliers.
//
// The written pseudocode says s<i, but a polynomial product requires s<=i;
// otherwise its constant and final coefficients are omitted.
func KeyGen(p Parameters) (*SecretKey, *PublicKey, error) {
	if err := p.Validate(); err != nil {
		return nil, nil, err
	}

	rows, cols := int(p.N+p.Lambda+1), int(p.M)
	f, h := make([]*big.Int, p.Lambda+1), make([]*big.Int, p.Lambda+1)
	beta := matrix(int(p.N)+1, cols)
	var err error

	for i := range f {
		if f[i], err = sampleMod(p.P); err != nil { return nil, nil, err }
		if h[i], err = sampleMod(p.P); err != nil { return nil, nil, err }
	}
	for i := range beta {
		for j := range beta[i] {
			if beta[i][j], err = sampleMod(p.P); err != nil { return nil, nil, err }
		}
	}

	// Algorithm 1: ell = 2 log2(p) + 8.
	ringBits := 2*uint(p.P.BitLen()) + 8
	r1, s1, err := hiddenRing(ringBits)
	if err != nil { return nil, nil, err }
	r2, s2, err := hiddenRing(ringBits)
	if err != nil { return nil, nil, err }

	P, Q := matrix(rows, cols), matrix(rows, cols)
	for i := 0; i < rows; i++ {
		for j := 0; j < cols; j++ {
			plainP, plainQ := new(big.Int), new(big.Int)
			for s := 0; s <= i; s++ {
				if s < len(f) && i-s < len(beta) {
					plainP.Add(plainP, new(big.Int).Mul(f[s], beta[i-s][j]))
					plainQ.Add(plainQ, new(big.Int).Mul(h[s], beta[i-s][j]))
				}
			}
			plainP.Mod(plainP, p.P)
			plainQ.Mod(plainQ, p.P)
			P[i][j].Mod(new(big.Int).Mul(r1, plainP), s1)
			Q[i][j].Mod(new(big.Int).Mul(r2, plainQ), s2)
		}
	}

	return &SecretKey{F: f, H: h, R1: r1, S1: s1, R2: r2, S2: s2},
		&PublicKey{Params: p, P: P, Q: Q}, nil
}
