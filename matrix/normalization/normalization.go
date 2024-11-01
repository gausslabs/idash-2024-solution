package normalization

import (
	"math"

	"app/matrix"
	"app/utils"

	"github.com/Pro7ech/lattigo/he"
	"github.com/Pro7ech/lattigo/he/hefloat"
	"github.com/Pro7ech/lattigo/rlwe"
)

type Parameters struct {
	Gamma           []float64
	Beta            []float64
	ToTVecSize      int
	InvSqrtMin      float64
	InvSqrtMax      float64
	InvSqrtDeg      int
	InvSqrtIter     int
	BootstrapBefore bool
	BootstrapAfter  bool
}

type Evaluator struct {
	Parameters
	*matrix.Evaluator
	he.Bootstrapper[rlwe.Ciphertext]
	InvSqrtPoly *he.Polynomial
}

func NewEvaluator(params Parameters, eval *matrix.Evaluator, btp he.Bootstrapper[rlwe.Ciphertext]) *Evaluator {

	f := func(x float64) (y float64) {
		return 1 / math.Sqrt(x)
	}

	return &Evaluator{
		Parameters:   params,
		Evaluator:    eval,
		Bootstrapper: btp,
		InvSqrtPoly:  utils.GetChebyshevPoly(params.InvSqrtMin, params.InvSqrtMax, params.InvSqrtDeg, f),
	}
}

func (eval *Evaluator) CircuitDepth() int {
	return 4 + 2*eval.InvSqrtIter + eval.InvSqrtPoly.Depth()
}

func GaloisElements(params hefloat.Parameters, k int) (galEls []uint64) {
	galEls = rlwe.GaloisElementsForInnerSum(params, 1, k)
	galEls = append(galEls, rlwe.GaloisElementsForReplicate(params, 1, k)...)
	return
}
