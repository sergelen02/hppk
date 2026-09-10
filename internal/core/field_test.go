package core

import (
	"math/big"
	"testing"
)

func TestFieldArithmeticDoesNotMutateInputs(t *testing.T) {
	f, err := NewField(big.NewInt(13))
	if err != nil { t.Fatal(err) }
	x, y := big.NewInt(12), big.NewInt(5)
	if got := f.Add(x, y); got.Cmp(big.NewInt(4)) != 0 { t.Fatalf("Add = %s, want 4", got) }
	if x.Cmp(big.NewInt(12)) != 0 || y.Cmp(big.NewInt(5)) != 0 { t.Fatal("field operation mutated an operand") }
	inv, err := f.Inv(big.NewInt(5))
	if err != nil || f.Mul(big.NewInt(5), inv).Cmp(big.NewInt(1)) != 0 { t.Fatalf("invalid inverse: %v, %v", inv, err) }
}
