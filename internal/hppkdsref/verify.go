package hppkdsref

import (
	"fmt"
	"math/big"
)

func validPK(pk *PublicKey) bool {
	if pk == nil || pk.S1 == nil || pk.S2 == nil || len(pk.PPrime) == 0 ||
		len(pk.PPrime) != len(pk.QPrime) || len(pk.PPrime) != len(pk.Mu) || len(pk.PPrime) != len(pk.Nu) {
		return false
	}
	for i := range pk.PPrime {
		if len(pk.PPrime[i]) != int(pk.Params.M) || len(pk.QPrime[i]) != int(pk.Params.M) ||
			len(pk.Mu[i]) != int(pk.Params.M) || len(pk.Nu[i]) != int(pk.Params.M) {
			return false
		}
	}
	return true
}

// Verify implements Algorithm 6. Q is masked in its own ring, hence its
// correction term uses s2 and nu; using s1 here would mix two rings.
func Verify(pk *PublicKey, sig *Signature, message []byte) (bool, error) {
	if !validPK(pk) || sig == nil || sig.F == nil || sig.H == nil {
		return false, fmt.Errorf("malformed public key or signature")
	}
	if err := pk.Params.Validate(); err != nil { return false, err }
	x, err := HashToField(pk.Params, message)
	if err != nil { return false, err }
	p := pk.Params.P
	R := new(big.Int).Lsh(big.NewInt(1), pk.Params.RBits)
	lhs, rhs, power := new(big.Int), new(big.Int), big.NewInt(1)
	for i := range pk.PPrime {
		for j := range pk.PPrime[i] {
			hMu := new(big.Int).Quo(new(big.Int).Mul(sig.H, pk.Mu[i][j]), R)
			fNu := new(big.Int).Quo(new(big.Int).Mul(sig.F, pk.Nu[i][j]), R)
			u := new(big.Int).Sub(new(big.Int).Mul(sig.H, pk.PPrime[i][j]), new(big.Int).Mul(pk.S1, hMu))
			v := new(big.Int).Sub(new(big.Int).Mul(sig.F, pk.QPrime[i][j]), new(big.Int).Mul(pk.S2, fNu))
			u.Mod(u, p); v.Mod(v, p)
			lhs.Add(lhs, new(big.Int).Mul(u, power)); lhs.Mod(lhs, p)
			rhs.Add(rhs, new(big.Int).Mul(v, power)); rhs.Mod(rhs, p)
		}
		power.Mul(power, x); power.Mod(power, p)
	}
	return lhs.Cmp(rhs) == 0, nil
}
