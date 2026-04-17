package ds

import (
	"math/big"

	"github.com/sergelen02/HPPK_2/internal/core"
)

func Verify(pk *Public, msg []byte, sig *Signature) bool {
	field := pk.Field
	x := core.HashToField(msg, pk.Params.HashName, field.P)
	if sig.X != nil && sig.X.Cmp(x) != 0 {
		return false
	}

	rows := pk.Params.N + pk.Params.Lambda + 1
	for j := 0; j < pk.Params.M; j++ {
		lhs := big.NewInt(0)
		rhs := big.NewInt(0)
		pow := big.NewInt(1)
		for i := 0; i < rows; i++ {
			uij := field.Sub(
				field.Mul(sig.H, pk.PPrime[i][j]),
				field.Mul(pk.S1Bar, core.FloorHRDivR(sig.H, pk.Mu[i][j], pk.Params.KBits)),
			)
			vij := field.Sub(
				field.Mul(sig.F, pk.QPrime[i][j]),
				field.Mul(pk.S2Bar, core.FloorHRDivR(sig.F, pk.Nu[i][j], pk.Params.KBits)),
			)
			lhs = field.Add(lhs, field.Mul(uij, pow))
			rhs = field.Add(rhs, field.Mul(vij, pow))
			pow = field.Mul(pow, x)
		}
		if lhs.Cmp(rhs) != 0 {
			return false
		}
	}
	return true
}
