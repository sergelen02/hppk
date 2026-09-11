package hppkdsref

import (
	_ "crypto/sha256"
	_ "crypto/sha512"
	"fmt"
	"math/big"
)

// HashToField maps a message deterministically into F_p.
func HashToField(p Parameters, message []byte) (*big.Int, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	h := p.Hash.New()
	if _, err := h.Write(message); err != nil {
		return nil, fmt.Errorf("hash message: %w", err)
	}
	return new(big.Int).Mod(new(big.Int).SetBytes(h.Sum(nil)), p.P), nil
}
