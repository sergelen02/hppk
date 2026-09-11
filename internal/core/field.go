// Package core implements arithmetic shared by every HPPK-DS variant.
package core

import (
	"errors"
	"math/big"
)

var ErrInvalidModulus = errors.New("field modulus must be an odd integer greater than two")

// Field is the prime field F_p. Methods never mutate their input operands.
type Field struct {
	P *big.Int
}

func NewField(p *big.Int) (*Field, error) {
	if p == nil || p.Cmp(big.NewInt(2)) <= 0 || p.Bit(0) == 0 {
		return nil, ErrInvalidModulus
	}
	return &Field{P: new(big.Int).Set(p)}, nil
}

func (f *Field) Normalize(x *big.Int) *big.Int {
	if x == nil {
		return new(big.Int)
	}
	return new(big.Int).Mod(new(big.Int).Set(x), f.P)
}

func (f *Field) Add(x, y *big.Int) *big.Int { return f.Normalize(new(big.Int).Add(x, y)) }
func (f *Field) Sub(x, y *big.Int) *big.Int { return f.Normalize(new(big.Int).Sub(x, y)) }
func (f *Field) Mul(x, y *big.Int) *big.Int { return f.Normalize(new(big.Int).Mul(x, y)) }

func (f *Field) Inv(x *big.Int) (*big.Int, error) {
	x = f.Normalize(x)
	if x.Sign() == 0 {
		return nil, errors.New("zero has no multiplicative inverse")
	}
	inv := new(big.Int).ModInverse(x, f.P)
	if inv == nil {
		return nil, errors.New("element is not invertible")
	}
	return inv, nil
}
