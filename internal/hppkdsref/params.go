// Package hppkdsref is reserved for the complete paper-reference HPPK-DS.
package hppkdsref

import (
	"crypto"
	"errors"
	"fmt"
	"math/big"

	"github.com/sergelen02/hppk/internal/core"
)

type Parameters struct {
	Name string
	P *big.Int
	N, Lambda, M uint
	L, RBits uint
	Hash crypto.Hash
}

func (p Parameters) Validate() error {
	if _, err := core.NewField(p.P); err != nil { return fmt.Errorf("invalid field: %w", err) }
	if p.N != 1 || p.Lambda != 1 || p.M != 1 { return errors.New("reference parameter sets currently require n=lambda=m=1") }
	if p.L == 0 || p.RBits <= p.L { return errors.New("require non-zero L and r_bits > L") }
	if !p.Hash.Available() { return errors.New("selected hash is unavailable") }
	return nil
}
