package softmax

import (
	"math"
	"slices"

	"golang.org/x/exp/maps"

	"app/matrix"
	"app/matrix/softmax/innermax"
	"app/utils"

	"github.com/Pro7ech/lattigo/he"
	"github.com/Pro7ech/lattigo/he/hefloat"
	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/rlwe"
	//"github.com/Pro7ech/lattigo/utils/bignum"
)

type Parameters struct {
	ExpOffset     float64
	ExpMin        float64 // Min x for exp(x)
	ExpMax        float64 // Max x for exp(x)
	ExpDeg        int     // Polynomial approximation degree of exp(x)
	InvMin        float64 // Min x for 1/x
	InvMax        float64 // Max x for 1/x
	InvDeg        int     // Polynomial approximation degree of 1/x
	K             int     // Vector size
	ToTVecSize    int     // K * nbMatrices
	MaxParameters innermax.Parameters
	InvSqrtIter   int
}

type Evaluator struct {
	Parameters
	ExpPoly *he.Polynomial
	InvPoly *he.Polynomial
	*matrix.Evaluator
	he.Bootstrapper[rlwe.Ciphertext]
}

func NewEvaluator(p Parameters, eval *matrix.Evaluator, btp he.Bootstrapper[rlwe.Ciphertext]) *Evaluator {

	fExp := func(x float64) (y float64) {
		return math.Exp(x)
	}

	var fInv func(x float64) (y float64)

	if p.InvSqrtIter > 0 {
		fInv = func(x float64) (y float64) {
			return 1 / math.Sqrt(x)
		}
	} else {
		fInv = func(x float64) (y float64) {
			return 1 / x
		}
	}

	return &Evaluator{
		Parameters:   p,
		ExpPoly:      utils.GetChebyshevPoly(p.ExpMin, p.ExpMax, p.ExpDeg, fExp),
		InvPoly:      utils.GetChebyshevPoly(p.InvMin, p.InvMax, p.InvDeg, fInv),
		Evaluator:    eval,
		Bootstrapper: btp,
	}
}

func GaloisElements(params hefloat.Parameters, k, numcts int) (galEls []uint64) {
	m := map[uint64]bool{}

	for _, galEl := range matrix.MaskAndCompressGaloisElements(params, k, numcts) {
		m[galEl] = true
	}

	for _, galEl := range rlwe.GaloisElementsForInnerSum(params, 1, k) {
		m[galEl] = true
	}

	for _, galEl := range rlwe.GaloisElementsForReplicate(params, 1, k) {
		m[galEl] = true
	}

	for _, galEl := range innermax.GaloisElements(params, k, numcts) {
		m[galEl] = true
	}

	if params.RingType() != ring.ConjugateInvariant {
		m[params.GaloisElementForComplexConjugation()] = true
	}

	galEls = maps.Keys(m)
	slices.Sort(galEls)

	return
}
