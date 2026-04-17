package core

import (
	"crypto/sha256"
	"crypto/sha512"
	"math/big"
)

func HashToField(msg []byte, hashName string, p *big.Int) *big.Int {
	var digest []byte
	switch hashName {
	case "sha256":
		h := sha256.Sum256(msg)
		digest = h[:]
	case "sha384":
		h := sha512.Sum384(msg)
		digest = h[:]
	case "sha512":
		h := sha512.Sum512(msg)
		digest = h[:]
	default:
		h := sha256.Sum256(msg)
		digest = h[:]
	}
	z := new(big.Int).SetBytes(digest)
	return new(big.Int).Mod(z, p)
}
