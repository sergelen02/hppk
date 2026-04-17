package kem
package kem

import (
	"math/big"

	"github.com/sergelen02/HPPK_2/internal/core"
)

func randomPoly(field *core.Field, degree int) *core.Poly {
	p := core.NewPoly(degree + 1)
	for i := 0; i <= degree; i++ {
		p.Coeff[i] = core.RandMod(field.P)
	}
	return p
}

func randomBetaCoeffs(field *core.Field, n, m int) [][]*big.Int {
	out := make([][]*big.Int, n+1)
	for i := 0; i <= n; i++ {
		out[i] = make([]*big.Int, m)
		for j := 0; j < m; j++ {
			out[i][j] = core.RandMod(field.P)
		}
	}
	return out
}


func evalPublicMatrices(field *core.Field, f, h *core.Poly, beta [][]*big.Int, n, lambda, m int) ([][]*big.Int, [][]*big.Int) {
	rows := n + lambda + 1
	P := make([][]*big.Int, rows)
	Q := make([][]*big.Int, rows)
	for i := 0; i < rows; i++ {
		P[i] = make([]*big.Int, m)
		Q[i] = make([]*big.Int, m)
		for j := 0; j < m; j++ {
			P[i][j] = big.NewInt(0)
			Q[i][j] = big.NewInt(0)
			for s := 0; s <= i; s++ {
				fi := i - s
				if fi >= 0 && fi < len(f.Coeff) && s < len(beta) {
					P[i][j] = field.Add(P[i][j], field.Mul(f.Coeff[fi], beta[s][j]))
					Q[i][j] = field.Add(Q[i][j], field.Mul(h.Coeff[fi], beta[s][j]))
				}
			}
		}
	}
	return P, Q
}

func KeyGen(params Params) (*Secret, *Public) {
	field := core.NewFieldFromDecimal(params.P)
	f := randomPoly(field, params.Lambda)
	h := randomPoly(field, params.Lambda)
	beta := randomBetaCoeffs(field, params.N, params.M)
	plainP, plainQ := evalPublicMatrices(field, f, h, beta, params.N, params.Lambda, params.M)

	S1 := core.RandBits(params.LBits)
	R1 := core.RandCoprime(S1, params.LBits)
	S2 := core.RandBits(params.LBits)
	R2 := core.RandCoprime(S2, params.LBits)

	rows := params.N + params.Lambda + 1
	encP := make([][]*big.Int, rows)
	encQ := make([][]*big.Int, rows)
	for i := 0; i < rows; i++ {
		encP[i] = make([]*big.Int, params.M)
		encQ[i] = make([]*big.Int, params.M)
		for j := 0; j < params.M; j++ {
			encP[i][j] = new(big.Int).Mod(new(big.Int).Mul(R1, plainP[i][j]), S1)
			encQ[i][j] = new(big.Int).Mod(new(big.Int).Mul(R2, plainQ[i][j]), S2)
		}
	}

	sk := &Secret{FPoly: f, HPoly: h, R1: R1, S1: S1, R2: R2, S2: S2, Field: field, Params: params}
	pk := &Public{PMatrix: encP, QMatrix: encQ, Field: field, Params: params}
	return sk, pk
}