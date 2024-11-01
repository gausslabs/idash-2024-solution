package softmax

import (
	"fmt"

	"github.com/Pro7ech/lattigo/he/hefloat"
	"app/matrix/softmax/innermax"
	"app/utils"

	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils/structs"
)

func (eval *Evaluator) EvaluateEncrypted(cts []rlwe.Ciphertext) (err error) {

	num := cts

	// a*(x - max(x))+b

	if err = eval.Normalize(num); err != nil {
		return
	}

	norm := make([]rlwe.Ciphertext, len(num))

	if err = utils.RunWithBench("SoftMax: Exp(x)", func() (LevelIn, LevelOut int, LogScaleIn, LogScaleOut float64, err error) {

		LevelIn = num[0].Level()
		LogScaleIn = num[0].LogScale()

		if num, err = eval.Polynomial(num, eval.ExpPoly); err != nil {
			return
		}

		norm = structs.Vector[rlwe.Ciphertext](num).Clone()

		if err = eval.Rescale(num, num); err != nil {
			return
		}

		LevelOut = num[0].Level()
		LogScaleOut = num[0].LogScale()

		return

	}); err != nil {
		return
	}

	aInv, bInv := eval.InvPoly.ChangeOfBasis()
	aInvF64, _ := aInv.Float64()
	bInvF64, _ := bInv.Float64()

	var ct *rlwe.Ciphertext
	if err = utils.RunWithBench("SoftMax: InnerSum + Mask & Compress ", func() (LevelIn, LevelOut int, LogScaleIn, LogScaleOut float64, err error) {

		LevelIn = norm[0].Level()
		LogScaleIn = norm[0].LogScale()

		if err = eval.InnerSum(norm, 1, eval.K, norm); err != nil {
			return
		}

		if err = eval.Rescale(norm, norm); err != nil {
			return
		}

		if ct, err = eval.MaskAndCompress(norm, aInvF64, bInvF64, eval.K, eval.ToTVecSize, true); err != nil {
			return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[matrix.MaskAndCompress]: %w", err)
		}

		LevelOut = ct.Level()
		LogScaleOut = ct.LogScale()

		return

	}); err != nil {
		return
	}

	if err = utils.RunWithBench("SoftMax: 1/x", func() (LevelIn, LevelOut int, LogScaleIn, LogScaleOut float64, err error) {

		LevelIn = ct.Level()
		LogScaleIn = ct.LogScale()

		if ct.Level() < eval.InvPoly.Depth() {
			if ct, err = eval.Bootstrap(ct); err != nil {
				return
			}
		}

		var half *rlwe.Ciphertext
		if eval.InvSqrtIter > 0 {

			if half, err = eval.Evaluators[0].SubNew(ct, bInvF64); err != nil {
				return
			}

			if err = eval.Evaluators[0].Mul(half, 0.5/(aInvF64*128), half); err != nil {
				return
			}

			if err = eval.Evaluators[0].Rescale(half, half); err != nil {
				return
			}
		}

		tmp := []rlwe.Ciphertext{*ct}
		if tmp, err = eval.Polynomial(tmp, eval.InvPoly); err != nil {
			return
		}
		if err = eval.Rescale(tmp, tmp); err != nil {
			return
		}
		ct = &tmp[0]

		if eval.InvSqrtIter > 0 {

			tmp = []rlwe.Ciphertext{*ct, *half}

			if tmp, err = eval.BootstrapMany(tmp); err != nil {
				return
			}

			ct = &tmp[0]
			half = &tmp[1]

			if err = eval.Evaluators[0].Mul(half, 128, half); err != nil {
				return
			}

			evalInv := hefloat.NewInverseEvaluator(eval.Evaluators[0].Parameters(), eval.Evaluators[0], nil)
			if err = evalInv.InvSqrt(ct, half, eval.InvSqrtIter); err != nil {
				return
			}

			if err = eval.Evaluators[0].MulRelin(ct, ct, ct); err != nil {
				return
			}

			if err = eval.Evaluators[0].Rescale(ct, ct); err != nil {
				return
			}

		} else {
			if ct, err = eval.Bootstrap(ct); err != nil {
				return
			}
		}

		LevelOut = ct.Level()
		LogScaleOut = ct.LogScale()

		return

	}); err != nil {
		return
	}

	if err = utils.RunWithBench("SoftMax: Extract", func() (LevelIn, LevelOut int, LogScaleIn, LogScaleOut float64, err error) {

		LevelIn = ct.Level()
		LogScaleIn = ct.LogScale()

		if norm, err = eval.Extract(ct, len(cts)); err != nil {
			return
		}

		if err = eval.MaskAndReplicate(norm, 1.0, eval.K, true); err != nil {
			return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[MaskAndReplicateEncrypted][ctLogF64,K]: %w", err)
		}

		LevelOut = norm[0].Level()
		LogScaleOut = norm[0].LogScale()

		return

	}); err != nil {
		return
	}

	if err = utils.RunWithBench("SoftMax: x*norm -> x", func() (LevelIn, LevelOut int, LogScaleIn, LogScaleOut float64, err error) {

		LevelIn = min(num[0].Level(), norm[0].Level())
		LogScaleIn = (norm[0].LogScale() + num[0].LogScale()) / 2

		if err = eval.DotCt(num, norm, num); err != nil {
			return
		}

		if err = eval.Rescale(num, cts); err != nil {
			return
		}

		LevelOut = cts[0].Level()
		LogScaleOut = cts[0].LogScale()

		return

	}); err != nil {
		return
	}

	return nil
}

func (eval *Evaluator) Normalize(cts []rlwe.Ciphertext) (err error) {

	aExp, bExp := eval.ExpPoly.ChangeOfBasis()
	aExpF64, _ := aExp.Float64()
	bExpF64, _ := bExp.Float64()

	max := structs.Vector[rlwe.Ciphertext](cts).Clone()

	maxEval := innermax.NewEvaluator(eval.MaxParameters, eval.Evaluator, eval.Bootstrapper)

	if max, err = maxEval.InnerMax(max, eval.K); err != nil {
		return fmt.Errorf("[InnerMax]: %w", err)
	}

	if err = eval.MaskAndReplicate(max, aExpF64, eval.K, false); err != nil {
		return fmt.Errorf("[matrix.Evaluator][MaxAndReplicate]: %w", err)
	}

	if err = eval.DropLevel(cts, cts[0].Level()-max[0].Level()); err != nil {
		return fmt.Errorf("[matrix.Evaluator][DropLevel]: %w", err)
	}

	if err = eval.MulScalar(cts, aExpF64, cts); err != nil {
		return fmt.Errorf("[matrix.Evaluator][MulScalar]: %w", err)
	}

	if err = eval.SubCt(cts, max, cts); err != nil {
		return fmt.Errorf("[matrix.Evaluator][SubVec]: %w", err)
	}

	if err = eval.AddScalar(cts, bExpF64+eval.ExpOffset*aExpF64, cts); err != nil {
		return fmt.Errorf("[matrix.Evaluator][AddScalar]: %w", err)
	}

	if err = eval.Rescale(cts, cts); err != nil {
		return fmt.Errorf("[matrix.Evaluator][Rescale]: %w", err)
	}

	return
}
