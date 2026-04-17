package core

import "math/big"

type Field struct {
	P *big.Int
}

func NewFieldFromDecimal(p string) *Field {
	z, ok := new(big.Int).SetString(p, 10)
	if !ok {
		panic("invalid field prime")
	}
	return &Field{P: z}
}

func (f *Field) Normalize(x *big.Int) *big.Int {
	z := new(big.Int).Mod(new(big.Int).Set(x), f.P)
	if z.Sign() < 0 {
		z.Add(z, f.P)
	}
	return z
}

func (f *Field) Add(a, b *big.Int) *big.Int {
	return f.Normalize(new(big.Int).Add(a, b))
}

func (f *Field) Sub(a, b *big.Int) *big.Int {
	return f.Normalize(new(big.Int).Sub(a, b))
}

func (f *Field) Mul(a, b *big.Int) *big.Int {
	return f.Normalize(new(big.Int).Mul(a, b))
}

func (f *Field) Inv(a *big.Int) *big.Int {
	z := new(big.Int).ModInverse(a, f.P)
	if z == nil {
		panic("inverse does not exist in field")
	}
	return z
}

func (f *Field) Div(a, b *big.Int) *big.Int {
	return f.Mul(a, f.Inv(b))
}
