package hppkdsref

import "math/big"

// SecretKey contains data that must never be serialized into benchmark output.
type SecretKey struct {
	F, H   []*big.Int
	R1, S1 *big.Int
	R2, S2 *big.Int
}

// PublicKey contains the Barrett-transformed public polynomial coefficients.
type PublicKey struct {
	Params                 Parameters
	PPrime, QPrime, Mu, Nu [][]*big.Int
	S1, S2                 *big.Int
}

// Signature is the pair of hidden-ring values specified by Algorithm 5.
type Signature struct {
	F, H *big.Int
}
