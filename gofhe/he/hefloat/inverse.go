package hefloat

import (
	"fmt"

	"app/gofhe/he"
	"app/gofhe/rlwe"
)

// InverseEvaluator is an evaluator used to evaluate the inverses of ciphertexts.
// All fields of this struct are public, enabling custom instantiations.
type InverseEvaluator struct {
	*Evaluator
	he.Bootstrapper[rlwe.Ciphertext]
	Parameters Parameters
}

// NewInverseEvaluator instantiates a new InverseEvaluator.
// The default hefloat.Evaluator is compliant to the EvaluatorForInverse interface.
// The field he.Bootstrapper[rlwe.Ciphertext] can be nil if the parameters have enough levels to support the computation.
// This method is allocation free.
func NewInverseEvaluator(params Parameters, eval *Evaluator, btp he.Bootstrapper[rlwe.Ciphertext]) InverseEvaluator {
	return InverseEvaluator{
		Evaluator:    eval,
		Bootstrapper: btp,
		Parameters:   params,
	}
}

// InvSqrt evaluates y = 1/sqrt(x) with r iterations of y = y * 1.5 - (x/2*y)*(y*y),
// which provides a quadratic convergence.
//
//   - cts: values already "rougthly" close to 1/sqrt(x). This can be done by first
//     evaluating a low-precision polynomial approximation of 1/sqrt(x).
//   - half: x/2
//
// The total depth is 2*r.
func (eval *InverseEvaluator) InvSqrt(in, inHalf *rlwe.Ciphertext, r int) (err error) {

	btp := eval.Bootstrapper

	params := eval.Parameters

	levelsPerRescaling := params.LevelsConsumedPerRescaling()

	for range r {

		if btp != nil && in.Level() < 2*levelsPerRescaling {
			if in, err = btp.Bootstrap(in); err != nil {
				return fmt.Errorf("[he.Bootstrapper][Bootstrap][in]: %w", err)
			}
		}

		// y = y * 1.5 - (x/2*y)*(y*y)
		var ysqrt *rlwe.Ciphertext
		if ysqrt, err = eval.MulRelinNew(in, in); err != nil {
			return fmt.Errorf("[hefloat.Evaluator][MulRelinNew][in, in]: %w", err)
		}

		if err = eval.Rescale(ysqrt, ysqrt); err != nil {
			return fmt.Errorf("[hefloat.Evaluator][Rescale][ysqrt, ysqrt]: %w", err)
		}

		if btp != nil && inHalf.Level() < in.Level() {
			if inHalf, err = btp.Bootstrap(inHalf); err != nil {
				return fmt.Errorf("[he.Bootstrapper][Bootstrap][inHalf]: %w", err)
			}
		}

		var xy *rlwe.Ciphertext
		if xy, err = eval.MulRelinNew(inHalf, in); err != nil {
			return fmt.Errorf("[hefloat.Evaluator][MulRelin][inHalf, in]: %w", err)
		}

		if err = eval.Rescale(xy, xy); err != nil {
			return fmt.Errorf("[hefloat.Evaluator][Rescale][xy, xy]: %w", err)
		}

		if err = eval.MulRelin(ysqrt, xy, ysqrt); err != nil {
			return fmt.Errorf("[hefloat.Evaluator][MulRelin][ysqrt, xy, ysqrt]: %w", err)
		}

		if err = eval.Mul(ysqrt, -1, ysqrt); err != nil {
			return fmt.Errorf("[hefloat.Evaluator][Mul][ysqrt, -1, ysqrt]: %w", err)
		}

		if err = eval.MulThenAdd(in, 1.5, ysqrt); err != nil {
			return fmt.Errorf("[hefloat.Evaluator][MulThenAdd][in, 1.5, ysqrt]: %w", err)
		}

		if err = eval.Rescale(ysqrt, in); err != nil {
			return fmt.Errorf("[hefloat.Evaluator][Rescale][ysqrt, in]: %w", err)
		}
	}

	return
}
