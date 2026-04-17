package ds
package ds

import (
	"math/big"

	"github.com/sergelen02/HPPK_2/internal/core"
)

type Params struct {
	Name     string `json:"name"`
	P        string `json:"p"`
	N        int    `json:"n"`
	Lambda   int    `json:"lambda"`
	M        int    `json:"m"`
	LBits    uint   `json:"l_bits"`
	KBits    uint   `json:"k_bits"`
	HashName string `json:"hash"`
}

type Secret struct {
	F       *core.Poly
	H       *core.Poly
	R1, S1  *big.Int
	R2, S2  *big.Int
	PMatrix [][]*big.Int
	QMatrix [][]*big.Int
	Field   *core.Field
	Params  Params
}

type Public struct {
	PPrime [][]*big.Int
	QPrime [][]*big.Int
	Mu     [][]*big.Int
	Nu     [][]*big.Int
	S1Bar  *big.Int
	S2Bar  *big.Int
	Field  *core.Field
	Params Params
}

type Signature struct {
	F *big.Int
	H *big.Int
	X *big.Int
}