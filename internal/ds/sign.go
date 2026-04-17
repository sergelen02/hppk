package ds
package ds

import (
	"math/big"

	"github.com/sergelen02/HPPK_2/internal/core"
)

func evaluateHiddenElement(field *core.Field, poly *core.Poly, x, rInv, s *big.Int) *big.Int {
	v := poly.Eval(field, x)
	mapped := new(big.Int).Mod(new(big.Int).Mul(rInv, v), s)
	return mapped
}

func Sign(sk *Secret, msg []byte) *Signature {
	field := sk.Field
	x := core.HashToField(msg, sk.Params.HashName, field.P)
	r1Inv := new(big.Int).ModInverse(sk.R1, sk.S1)
	r2Inv := new(big.Int).ModInverse(sk.R2, sk.S2)
	if r1Inv == nil || r2Inv == nil {
		panic("secret key is invalid: inverse does not exist")
	}

	Fsig := evaluateHiddenElement(field, sk.F, x, r2Inv, sk.S2)
	Hsig := evaluateHiddenElement(field, sk.H, x, r1Inv, sk.S1)
	return &Signature{F: Fsig, H: Hsig, X: x}
}