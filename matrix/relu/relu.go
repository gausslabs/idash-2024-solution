package relu

import (
	"app/matrix"

	"app/gofhe/he"
	"app/gofhe/rlwe"
)

type Evaluator struct {
	Parameters
	*matrix.Evaluator
	he.Bootstrapper[rlwe.Ciphertext]
}

func NewEvaluator(p Parameters, eval *matrix.Evaluator, btp he.Bootstrapper[rlwe.Ciphertext]) *Evaluator {
	return &Evaluator{
		Parameters:   p,
		Evaluator:    eval,
		Bootstrapper: btp,
	}
}

type Parameters struct {
	CoeffsFloat  [][]float64
	CoeffsString [][]string
	AbsMax       float64
}
