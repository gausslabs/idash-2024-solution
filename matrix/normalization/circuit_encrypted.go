package normalization

import (
	"fmt"

	"app/utils"

	"github.com/Pro7ech/lattigo/he/hefloat"
	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils/structs"
)

func (eval *Evaluator) EvaluateEncrypted(in []rlwe.Ciphertext, k int) (err error) {

	params := eval.Evaluators[0].Parameters()

	scalar, constant := eval.InvSqrtPoly.ChangeOfBasis()
	AF64, _ := scalar.Float64()
	BF64, _ := constant.Float64()

	polyEval := hefloat.NewPolynomialEvaluator(params, eval.Evaluators[0])
	invEval := hefloat.NewInverseEvaluator(params, eval.Evaluators[0], eval.Bootstrapper)

	variances := structs.Vector[rlwe.Ciphertext](in).Clone()

	if err = utils.RunWithBench("Normalization: E[x]", func() (LevelIn, LevelOut int, LogScaleIn, LogScaleOut float64, err error) {

		LevelIn = in[0].Level()
		LogScaleIn = in[0].LogScale()

		if err = eval.InnerSum(variances, 1, k, variances); err != nil {
			return
		}

		// 1 Level
		if err = eval.MaskAndReplicate(variances, 1/float64(k), k, true); err != nil {
			return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[matrix.MaxAndReplicate]: %w", err)
		}

		LevelOut = variances[0].Level()
		LogScaleOut = variances[0].LogScale()

		return

	}); err != nil {
		return
	}

	if err = utils.RunWithBench("Normalization: Var[x]", func() (LevelIn, LevelOut int, LogScaleIn, LogScaleOut float64, err error) {

		LevelIn = variances[0].Level()
		LogScaleIn = variances[0].LogScale()

		// 1 Level
		if err = eval.SubCt(in, variances, in); err != nil {
			return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[matrix.Evaluator][SubCt][in,mean,in]: %w", err)
		}

		if err = eval.DotCt(in, in, variances); err != nil {
			return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[matrix.Evaluator][DotCt][in,in,in]: %w", err)
		}

		if err = eval.InnerSum(variances, 1, k, variances); err != nil {
			return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[matrix.Evaluator][InnerSum][variances]: %w", err)
		}

		if err = eval.Rescale(variances, variances); err != nil {
			return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[matrix.Evaluator][Rescale][variance,variance]: %w", err)
		}

		if err = eval.AddScalar(variances, 1e-6, variances); err != nil {
			return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[matrix.Evaluator][AddScalar][variance,1e-6,variances]: %w", err)
		}

		if eval.BootstrapBefore {
			eval.DropLevel(variances, variances[0].Level()-1)
		}

		var half *rlwe.Ciphertext
		if eval.InvSqrtIter > 0 {
			if half, err = eval.MaskAndCompress(structs.Vector[rlwe.Ciphertext](variances).Clone(), 1/float64(2*k), 0, k, eval.ToTVecSize, true); err != nil {
				return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[matrix.MaskAndCompress]: %w", err)
			}
		}

		var variance *rlwe.Ciphertext
		if variance, err = eval.MaskAndCompress(variances, AF64/float64(k), BF64, k, eval.ToTVecSize, true); err != nil {
			return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[matrix.MaskAndCompress]: %w", err)
		}

		if eval.BootstrapBefore {
			if eval.InvSqrtIter > 0 {
				tmp := []rlwe.Ciphertext{*variance, *half}
				if tmp, err = eval.Bootstrapper.BootstrapMany(tmp); err != nil {
					return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[hefloat.Bootstrapper][BootstrapMany][variance, half]: %w", err)
				}
				variance = &tmp[0]
				half = &tmp[1]
			} else {
				if variance, err = eval.Bootstrapper.Bootstrap(variance); err != nil {
					return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[hefloat.Bootstrapper][BootstrapMany][variance]: %w", err)
				}
			}
		}

		if eval.BootstrapAfter {
			eval.Evaluators[0].DropLevel(variance, variance.Level()-eval.InvSqrtPoly.Depth()-2*eval.InvSqrtIter)
		}

		if err = utils.RunWithBench("Normalization: Poly", func() (LevelIn, LevelOut int, LogScaleIn, LogScaleOut float64, err error) {

			LevelIn = variance.Level()
			LogScaleIn = variance.LogScale()

			if variance, err = polyEval.Evaluate(variance, eval.InvSqrtPoly, params.DefaultScale()); err != nil {
				return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[hefloat.PolynomialEvaluator][Evaluate][variance,eval.InvSqrtPoly,variance.Scale]: %w", err)
			}

			if err = polyEval.Rescale(variance, variance); err != nil {
				return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[hefloat.Evaluator][Rescale][variance,variance]: %w", err)
			}

			LevelOut = variance.Level()
			LogScaleOut = variance.LogScale()

			return

		}); err != nil {
			return
		}

		if eval.InvSqrtIter > 0 {
			if err = utils.RunWithBench("Normalization: Newton", func() (LevelIn, LevelOut int, LogScaleIn, LogScaleOut float64, err error) {

				LevelIn = variance.Level()
				LogScaleIn = variance.LogScale()

				if err = invEval.InvSqrt(variance, half, eval.InvSqrtIter); err != nil {
					return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[hefloat.InverseEvaluator][InvSqrtQuadratic][variance,half,eval.InvSqrtIter]: %w", err)
				}

				LevelOut = variance.Level()
				LogScaleOut = variance.LogScale()

				return

			}); err != nil {
				return
			}
		}

		if eval.BootstrapAfter {
			if variance, err = eval.Bootstrapper.Bootstrap(variance); err != nil {
				return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[hefloat.Bootstrapper][BootstrapMany][variances]: %w", err)
			}
		}

		if variances, err = eval.Extract(variance, len(variances)); err != nil {
			return
		}

		if err = eval.MaskAndReplicate(variances, 1, k, true); err != nil {
			return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[matrix.MaxAndReplicate]: %w", err)
		}

		LevelOut = variances[0].Level()
		LogScaleOut = variances[0].LogScale()

		return

	}); err != nil {
		return
	}

	beta := make([]float64, params.MaxSlots())
	gamma := make([]float64, params.MaxSlots())
	for i := range len(gamma) / k {
		copy(gamma[i*k:], eval.Gamma)
		copy(beta[i*k:], eval.Beta)
	}

	if err = utils.RunWithBench("Normalization: (x-E[x])/Sqrt(Var[x]) * gamma + beta", func() (LevelIn, LevelOut int, LogScaleIn, LogScaleOut float64, err error) {

		LevelIn = variances[0].Level()
		LogScaleIn = variances[0].LogScale()

		if err = eval.DotVec(in, gamma, in); err != nil {
			return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[matrix.Evaluator][DotVec][in,gamma,in]: %w", err)
		}

		if err = eval.Rescale(in, in); err != nil {
			return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[matrix.Evaluator][Rescale][in,in]: %w", err)
		}

		if err = eval.DotCt(in, variances, in); err != nil {
			return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[matrix.Evaluator][DotVec][in,invstd,in]: %w", err)
		}

		if err = eval.Rescale(in, in); err != nil {
			return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[matrix.Evaluator][Rescale][in,in]: %w", err)
		}

		if err = eval.AddVec(in, beta, in); err != nil {
			return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[hefloat.Evaluator][Add][in[i],beta,in[i]]: %w", err)
		}

		LevelOut = in[0].Level()
		LogScaleOut = in[0].LogScale()

		return

	}); err != nil {
		return
	}

	return
}
