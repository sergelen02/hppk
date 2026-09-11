// Package hppkkemref implements the paper-reference HPPK KEM separately
// from HPPK-DS.
package hppkkemref

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/sergelen02/hppk/internal/core"
)

type Parameters struct {
	Name         string
	P            *big.Int
	N, Lambda, M uint
}

func (p Parameters) Validate() error {
	if _, err := core.NewField(p.P); err != nil {
		return fmt.Errorf("invalid field: %w", err)
	}
	if p.M == 0 {
		return errors.New("m must be non-zero")
	}
	return nil
}

// SecretKey is Algorithm 1's private key: f, h and both hidden-ring pairs.
type SecretKey struct {
	F, H   []*big.Int
	R1, S1 *big.Int
	R2, S2 *big.Int
}

// PublicKey is Algorithm 1's encrypted coefficient matrices P and Q.
type PublicKey struct {
	Params Parameters
	P, Q   [][]*big.Int
}
