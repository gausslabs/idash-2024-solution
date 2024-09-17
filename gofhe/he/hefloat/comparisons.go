package hefloat

import (
	"math/big"

	"app/gofhe/he"
	"app/gofhe/rlwe"
	"app/gofhe/utils/bignum"
)

// ComparisonEvaluator is an evaluator providing an API for homomorphic comparisons.
// All fields of this struct are public, enabling custom instantiations.
type ComparisonEvaluator struct {
	MinimaxCompositePolynomialEvaluator
	MinimaxCompositeSignPolynomial MinimaxCompositePolynomial
}

// NewComparisonEvaluator instantiates a new ComparisonEvaluator.
// The default hefloat.Evaluator is compliant with the EvaluatorForMinimaxCompositePolynomial interface.
// The field he.Bootstrapper[rlwe.Ciphertext] can be nil if the parameters have enough level to support the computation.
//
// Giving a MinimaxCompositePolynomial is optional, but it is highly recommended to provide one that is optimized
// for the circuit requiring the comparisons as this polynomial will define the internal precision of all computations
// performed by this evaluator.
//
// The MinimaxCompositePolynomial must be a composite minimax approximation of the sign function:
// f(x) = 1 if x > 0, -1 if x < 0, else 0, in the interval [-1, 1].
// Such composite polynomial can be obtained with the function GenMinimaxCompositePolynomialForSign.
//
// If no MinimaxCompositePolynomial is given, then it will use by default the variable DefaultMinimaxCompositePolynomialForSign.
// See the doc of DefaultMinimaxCompositePolynomialForSign for additional information about the performance of this approximation.
//
// This method is allocation free if a MinimaxCompositePolynomial is given.
func NewComparisonEvaluator(params Parameters, eval EvaluatorForMinimaxCompositePolynomial, bootstrapper he.Bootstrapper[rlwe.Ciphertext], signPoly MinimaxCompositePolynomial) *ComparisonEvaluator {
	return &ComparisonEvaluator{*NewMinimaxCompositePolynomialEvaluator(params, eval, bootstrapper), signPoly}
}

// Step evaluates f(x) = 1 if x > 0, 0 if x < 0, else 0.5 (i.e. (sign+1)/2).
// This will ensure that step.Scale = params.DefaultScale().
func (eval ComparisonEvaluator) Step(op0 *rlwe.Ciphertext) (step *rlwe.Ciphertext, err error) {

	n := len(eval.MinimaxCompositeSignPolynomial)

	stepPoly := make([]bignum.Polynomial, n)

	for i := 0; i < n; i++ {
		stepPoly[i] = eval.MinimaxCompositeSignPolynomial[i]
	}

	half := new(big.Float).SetFloat64(0.5)

	// (x+1)/2
	lastPoly := eval.MinimaxCompositeSignPolynomial[n-1].Clone()
	for i := range lastPoly.Coeffs {
		lastPoly.Coeffs[i][0].Mul(&lastPoly.Coeffs[i][0], half)
	}
	lastPoly.Coeffs[0][0].Add(&lastPoly.Coeffs[0][0], half)

	stepPoly[n-1] = *lastPoly

	return eval.Evaluate(op0, stepPoly, op0.Scale)
}

func (eval ComparisonEvaluator) stepdiff(op0, op1 *rlwe.Ciphertext) (stepdiff *rlwe.Ciphertext, err error) {
	params := eval.Parameters

	// diff = op0 - op1
	var diff *rlwe.Ciphertext
	if diff, err = eval.SubNew(op0, op1); err != nil {
		return
	}

	// Required for the scale matching before the last multiplication.
	if diff.Level() < params.LevelsConsumedPerRescaling()*2 {
		if diff, err = eval.Bootstrap(diff); err != nil {
			return
		}
	}

	// step = 1 if diff > 0, 0 if diff < 0 else 0.5
	var step *rlwe.Ciphertext
	if step, err = eval.Step(diff); err != nil {
		return
	}

	// Required for the following multiplication
	if step.Level() < params.LevelsConsumedPerRescaling() {
		if step, err = eval.Bootstrap(step); err != nil {
			return
		}
	}

	// Extremum gate: op0 * step + op1 * (1 - step) = step * diff + op1
	level := min(diff.Level(), step.Level())

	ratio := rlwe.NewScale(1)
	for i := 0; i < params.LevelsConsumedPerRescaling(); i++ {
		ratio = ratio.Mul(rlwe.NewScale(params.Q()[level-i]))
	}

	ratio = ratio.Div(diff.Scale)
	if err = eval.Mul(diff, &ratio.Value, diff); err != nil {
		return
	}

	if err = eval.Rescale(diff, diff); err != nil {
		return
	}
	diff.Scale = diff.Scale.Mul(ratio)

	// max = step * diff
	if err = eval.MulRelin(diff, step, diff); err != nil {
		return
	}

	if err = eval.Rescale(diff, diff); err != nil {
		return
	}

	return diff, nil
}
