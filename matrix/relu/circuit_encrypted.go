package relu

import (
	"fmt"
	"math/big"

	"github.com/Pro7ech/lattigo/he"
	"github.com/Pro7ech/lattigo/he/hefloat"
	"github.com/Pro7ech/lattigo/rlwe"
)

func (eval *Evaluator) EvaluateEncrypted(in []rlwe.Ciphertext) (err error) {

	var step []rlwe.Ciphertext
	if step, err = eval.Step(in); err != nil {
		return fmt.Errorf("[hefloat.ComparisonEvaluator][Step]: %w", err)
	}

	if err = eval.Rescale(step, step); err != nil {
		return fmt.Errorf("[matrix.Evaluator][Rescale][step,step]: %w", err)
	}

	if err = eval.DotCt(in, step, in); err != nil {
		return fmt.Errorf("[matrix.Evaluator][DotCt][in,step,in]: %w", err)
	}

	if err = eval.Rescale(in, in); err != nil {
		return fmt.Errorf("[matrix.Evaluator][Rescale][in,in]: %w", err)
	}

	return
}

// Step evaluates f(x) = 1 if x > 0, 0 if x < 0, else 0.5 (i.e. (sign+1)/2).
// This will ensure that step.Scale = params.DefaultScale().
func (eval *Evaluator) Step(in []rlwe.Ciphertext) (out []rlwe.Ciphertext, err error) {

	polyCMP := hefloat.NewMinimaxCompositePolynomial(eval.CoeffsString)

	n := len(polyCMP)

	stepPoly := make([]*he.Polynomial, n)

	for i := 0; i < n; i++ {
		stepPoly[i] = he.NewPolynomial(&polyCMP[i])
	}

	half := new(big.Float).SetFloat64(0.5)

	// (x+1)/2
	lastPoly := polyCMP[n-1].Clone()
	for i := range lastPoly.Coeffs {
		lastPoly.Coeffs[i][0].Mul(&lastPoly.Coeffs[i][0], half)
	}
	lastPoly.Coeffs[0][0].Add(&lastPoly.Coeffs[0][0], half)

	stepPoly[n-1] = he.NewPolynomial(lastPoly)

	if out, err = eval.Polynomial(in, stepPoly[0]); err != nil {
		return nil, fmt.Errorf("[matrix.Evaluator][Polynomial][in,stepPoly]: %w", err)
	}

	for i := 1; i < len(stepPoly); i++ {

		if err = eval.Rescale(out, out); err != nil {
			return nil, fmt.Errorf("[matrix.Evaluator][Rescale][out,out]: %w", err)
		}

		if out[0].Level() < stepPoly[i].Depth() {
			if out, err = eval.BootstrapMany(out); err != nil {
				return nil, fmt.Errorf("btp.BootstrapMany: %w", err)
			}
		}

		if out, err = eval.Polynomial(out, stepPoly[i]); err != nil {
			return nil, fmt.Errorf("[matrix.Evaluator][Polynomial][out,stepPoly]: %w", err)
		}
	}

	return
}
