package matrix

import (
	"fmt"

	"app/concurrency"

	"gonum.org/v1/gonum/mat"

	"app/gofhe/he"
	"app/gofhe/he/hefloat"
	"app/gofhe/ring"
	"app/gofhe/rlwe"
)

type Evaluator struct {
	Evaluators []*hefloat.Evaluator
	params     hefloat.Parameters
	dims       int
}

func NewEvaluator(params hefloat.Parameters, dims int, eval []*hefloat.Evaluator) (evalMat *Evaluator) {
	evalMat = new(Evaluator)
	evalMat.params = params
	evalMat.Evaluators = eval
	evalMat.dims = dims
	return
}

func (eval *Evaluator) SetKeys(evk rlwe.EvaluationKeySet) {
	for i := range eval.Evaluators {
		eval.Evaluators[i] = eval.Evaluators[i].WithKey(evk)
	}
}

func (eval *Evaluator) MatchScalesForMul(A, B []rlwe.Ciphertext, targetScale rlwe.Scale) (err error) {
	m := concurrency.NewRessourceManager[*hefloat.Evaluator](eval.Evaluators)
	for i := range A {
		m.Run(func(eval *hefloat.Evaluator) (err error) {
			return eval.MatchScalesForMul(&A[i], &B[i], targetScale)
		})
	}
	return m.Wait()
}

func (eval *Evaluator) SetScale(A []rlwe.Ciphertext, scale rlwe.Scale) (err error) {
	m := concurrency.NewRessourceManager[*hefloat.Evaluator](eval.Evaluators)
	for i := range A {
		m.Run(func(eval *hefloat.Evaluator) (err error) {
			return eval.SetScale(&A[i], scale)
		})
	}
	return m.Wait()
}

func (eval *Evaluator) InnerSum(A []rlwe.Ciphertext, n, k int, B []rlwe.Ciphertext) (err error) {
	m := concurrency.NewRessourceManager[*hefloat.Evaluator](eval.Evaluators)
	for i := range A {
		m.Run(func(eval *hefloat.Evaluator) (err error) {
			return eval.InnerSum(&A[i], n, k, &B[i])
		})
	}
	return m.Wait()
}

func (eval *Evaluator) Replicate(A []rlwe.Ciphertext, n, k int, B []rlwe.Ciphertext) (err error) {
	m := concurrency.NewRessourceManager[*hefloat.Evaluator](eval.Evaluators)
	for i := range A {
		m.Run(func(eval *hefloat.Evaluator) (err error) {
			return eval.Replicate(&A[i], n, k, &B[i])
		})
	}
	return m.Wait()
}

func (eval *Evaluator) DropLevel(A []rlwe.Ciphertext, levels int) (err error) {
	m := concurrency.NewRessourceManager[*hefloat.Evaluator](eval.Evaluators)
	for i := range A {
		m.Run(func(eval *hefloat.Evaluator) (err error) {
			eval.DropLevel(&A[i], levels)
			return
		})
	}
	return m.Wait()
}

func (eval *Evaluator) Rescale(A, B []rlwe.Ciphertext) (err error) {
	m := concurrency.NewRessourceManager[*hefloat.Evaluator](eval.Evaluators)
	for i := range A {
		m.Run(func(eval *hefloat.Evaluator) (err error) {
			return eval.Rescale(&A[i], &B[i])
		})
	}

	return m.Wait()
}

func (eval *Evaluator) AddCt(A, B, C []rlwe.Ciphertext) (err error) {
	m := concurrency.NewRessourceManager[*hefloat.Evaluator](eval.Evaluators)
	for i := range A {
		m.Run(func(eval *hefloat.Evaluator) (err error) {
			return eval.Add(&A[i], &B[i], &C[i])
		})
	}
	return m.Wait()
}

func (eval *Evaluator) SubCt(A, B, C []rlwe.Ciphertext) (err error) {
	m := concurrency.NewRessourceManager[*hefloat.Evaluator](eval.Evaluators)
	for i := range A {
		m.Run(func(eval *hefloat.Evaluator) (err error) {
			return eval.Sub(&A[i], &B[i], &C[i])
		})
	}
	return m.Wait()
}

func (eval *Evaluator) DotCt(A, B, C []rlwe.Ciphertext) (err error) {
	m := concurrency.NewRessourceManager[*hefloat.Evaluator](eval.Evaluators)
	for i := range A {
		m.Run(func(eval *hefloat.Evaluator) (err error) {
			return eval.MulRelin(&A[i], &B[i], &C[i])
		})
	}
	return m.Wait()
}

func (eval *Evaluator) DotVec(A []rlwe.Ciphertext, B []float64, C []rlwe.Ciphertext) (err error) {

	level := min(A[0].Level(), C[0].Level())
	params := eval.Evaluators[0].Parameters()
	pt := hefloat.NewPlaintext(params, level)
	pt.Scale = params.GetScalingFactor(A[0].Scale, params.DefaultScale(), level)
	if err = eval.Evaluators[0].Encode(B, pt); err != nil {
		return
	}

	m := concurrency.NewRessourceManager[*hefloat.Evaluator](eval.Evaluators)
	for i := range A {
		m.Run(func(eval *hefloat.Evaluator) (err error) {
			return eval.Mul(&A[i], pt, &C[i])
		})
	}
	return m.Wait()
}

func (eval *Evaluator) AddVec(A []rlwe.Ciphertext, B []float64, C []rlwe.Ciphertext) (err error) {

	level := min(A[0].Level(), C[0].Level())
	params := eval.Evaluators[0].Parameters()
	pt := hefloat.NewPlaintext(params, level)
	pt.Scale = A[0].Scale
	if err = eval.Evaluators[0].Encode(B, pt); err != nil {
		return
	}

	m := concurrency.NewRessourceManager[*hefloat.Evaluator](eval.Evaluators)
	for i := range A {
		m.Run(func(eval *hefloat.Evaluator) (err error) {
			return eval.Add(&A[i], pt, &C[i])
		})
	}
	return m.Wait()
}

func (eval *Evaluator) SubVec(A []rlwe.Ciphertext, B []float64, C []rlwe.Ciphertext) (err error) {

	level := min(A[0].Level(), C[0].Level())
	params := eval.Evaluators[0].Parameters()
	pt := hefloat.NewPlaintext(params, level)
	pt.Scale = A[0].Scale
	if err = eval.Evaluators[0].Encode(B, pt); err != nil {
		return
	}

	m := concurrency.NewRessourceManager[*hefloat.Evaluator](eval.Evaluators)
	for i := range A {
		m.Run(func(eval *hefloat.Evaluator) (err error) {
			return eval.Sub(&A[i], pt, &C[i])
		})
	}
	return m.Wait()
}

func (eval *Evaluator) AddScalar(A []rlwe.Ciphertext, B float64, C []rlwe.Ciphertext) (err error) {
	m := concurrency.NewRessourceManager[*hefloat.Evaluator](eval.Evaluators)
	for i := range A {
		m.Run(func(eval *hefloat.Evaluator) (err error) {
			return eval.Add(&A[i], B, &C[i])
		})
	}
	return m.Wait()
}

func (eval *Evaluator) MulScalar(A []rlwe.Ciphertext, B float64, C []rlwe.Ciphertext) (err error) {
	m := concurrency.NewRessourceManager[*hefloat.Evaluator](eval.Evaluators)
	for i := range A {
		m.Run(func(eval *hefloat.Evaluator) (err error) {
			return eval.Mul(&A[i], B, &C[i])
		})
	}
	return m.Wait()
}

func (eval *Evaluator) AddPt(A []rlwe.Ciphertext, B *mat.Dense, C []rlwe.Ciphertext) (err error) {
	level := min(A[0].Level(), C[0].Level())
	params := eval.Evaluators[0].Parameters()
	pt := hefloat.NewPlaintext(params, level)
	pt.Scale = A[0].Scale

	if err = eval.Evaluators[0].Encode(Flatten(B, params.MaxSlots()), pt); err != nil {
		return fmt.Errorf("[hefloat.Encoder][Encode]: %w", err)
	}

	m := concurrency.NewRessourceManager[*hefloat.Evaluator](eval.Evaluators)

	for i := range A {
		m.Run(func(eval *hefloat.Evaluator) (err error) {
			return eval.Add(&A[i], pt, &C[i])
		})
	}

	return m.Wait()
}

func (eval *Evaluator) MulPt(A []rlwe.Ciphertext, B *Plaintext, C []rlwe.Ciphertext) (err error) {
	m := concurrency.NewRessourceManager[*hefloat.Evaluator](eval.Evaluators)
	for i := range A {
		m.Run(func(eval *hefloat.Evaluator) (err error) {
			if err = he.NewLinearTransformationEvaluator(eval).Evaluate(&A[i], B.LinearTransformation, &C[i]); err != nil {
				return fmt.Errorf("[he.LinearTransformationEvaluator].Evaluate: %w", err)
			}
			return
		})
	}
	return m.Wait()
}

func (eval *Evaluator) EvaluateLinearTransformation(A []rlwe.Ciphertext, lt *he.LinearTransformation, B []rlwe.Ciphertext) (err error) {
	m := concurrency.NewRessourceManager[*hefloat.Evaluator](eval.Evaluators)
	for i := range A {
		m.Run(func(eval *hefloat.Evaluator) (err error) {
			if err = he.NewLinearTransformationEvaluator(eval).Evaluate(&A[i], lt, &B[i]); err != nil {
				return fmt.Errorf("[matrix.Evaluator][TransposeMany]: %w", err)
			}
			return
		})
	}

	return m.Wait()
}

func (eval *Evaluator) Polynomial(A []rlwe.Ciphertext, poly *he.Polynomial) (B []rlwe.Ciphertext, err error) {
	B = make([]rlwe.Ciphertext, len(A))
	m := concurrency.NewRessourceManager[*hefloat.Evaluator](eval.Evaluators)
	for i := range A {
		m.Run(func(eval *hefloat.Evaluator) (err error) {
			params := eval.Parameters()
			polyEval := hefloat.NewPolynomialEvaluator(params, eval)
			var ct *rlwe.Ciphertext
			if ct, err = polyEval.Evaluate(&A[i], poly, params.DefaultScale()); err != nil {
				return
			}
			B[i] = *ct
			return
		})
	}

	return B, m.Wait()
}

func (eval *Evaluator) MulCt(A, B []rlwe.Ciphertext, mulParams *MulParameters, C []rlwe.Ciphertext) (err error) {

	params := eval.Evaluators[0].Parameters()

	type evaluator struct {
		*hefloat.Evaluator
		*evaluatorBuffer
	}

	evaluators := make([]*evaluator, len(eval.Evaluators))
	for i := range evaluators {
		evaluators[i] = &evaluator{
			Evaluator:       eval.Evaluators[i],
			evaluatorBuffer: newEvaluatorBuffer(params, eval.dims),
		}
	}

	m := concurrency.NewRessourceManager[*evaluator](evaluators)
	for i := range A {

		m.Run(func(eval *evaluator) (err error) {
			var ct *rlwe.Ciphertext
			if ct, err = squaredMatMul(&A[i], &B[i], mulParams, eval.Evaluator, eval.evaluatorBuffer, &C[i]); err != nil {
				return fmt.Errorf("[matrix.Evaluator].mul: %w", err)
			}
			C[i] = *ct
			return
		})
	}

	return m.Wait()
}

type evaluatorBuffer struct {
	BufA         []ring.Poly
	BufB         []ring.Poly
	BufC         []ring.Poly
	BufAB        []ring.Poly
	BufARescaled [2]ring.Poly
	BufBRescaled [2]ring.Poly
	BufDecompQPB [][2]ring.Poly
}

func newEvaluatorBuffer(params hefloat.Parameters, dim int) (buff *evaluatorBuffer) {

	buff = new(evaluatorBuffer)

	rQ := params.RingQ()
	rP := params.RingP()
	level := params.MaxLevel()

	buff.BufA = []ring.Poly{rQ.NewPoly(), rQ.NewPoly()}
	buff.BufB = []ring.Poly{rQ.NewPoly(), rQ.NewPoly()}
	buff.BufAB = []ring.Poly{rQ.NewPoly(), rQ.NewPoly()}

	buff.BufDecompQPB = make([][2]ring.Poly, len(params.DecompositionMatrixDimensions(params.MaxLevelQ(), params.MaxLevelP(), rlwe.DigitDecomposition{})))
	for i := range buff.BufDecompQPB {
		buff.BufDecompQPB[i][0] = rQ.NewPoly()
		buff.BufDecompQPB[i][1] = rP.NewPoly()
	}

	rQ = rQ.AtLevel(level - 1)

	buff.BufC = []ring.Poly{rQ.NewPoly(), rQ.NewPoly()}

	buff.BufARescaled = [2]ring.Poly{rQ.NewPoly(), rQ.NewPoly()}
	buff.BufBRescaled = [2]ring.Poly{rQ.NewPoly(), rQ.NewPoly()}

	return
}

func squaredMatMul(A, B *rlwe.Ciphertext, mulParams *MulParameters, eval *hefloat.Evaluator, buff *evaluatorBuffer, C *rlwe.Ciphertext) (*rlwe.Ciphertext, error) {

	level := min(A.Level(), B.Level())
	level = min(level, C.Level())

	if level < mulParams.Level() {
		return nil, fmt.Errorf("invalid inputs: min(A.Level(), B.Level(), C.Level()) < mulParams.Level()")
	}

	params := eval.Parameters()

	rQ := params.RingQ()
	alpha := params.PCount()
	levelP := alpha - 1
	bufDecompQPA := eval.BuffDecompQP
	bufDecompQPB := buff.BufDecompQPB

	bufA, err := rlwe.NewCiphertextAtLevelFromPoly(level, -1, buff.BufA, nil)
	if err != nil {
		panic(err)
	}
	bufA.IsNTT = true

	bufB, err := rlwe.NewCiphertextAtLevelFromPoly(level, -1, buff.BufB, nil)
	if err != nil {
		panic(err)
	}
	bufB.IsNTT = true

	bufC, err := rlwe.NewCiphertextAtLevelFromPoly(level-1, -1, buff.BufC, nil)
	if err != nil {
		panic(err)
	}
	bufC.IsNTT = true

	bufARescaled, err := rlwe.NewCiphertextAtLevelFromPoly(level-1, -1, buff.BufARescaled[:], nil)
	if err != nil {
		panic(err)
	}
	bufARescaled.IsNTT = true

	bufBRescaled, err := rlwe.NewCiphertextAtLevelFromPoly(level-1, -1, buff.BufBRescaled[:], nil)
	if err != nil {
		panic(err)
	}
	bufBRescaled.IsNTT = true

	// Row & Cols permutations
	evalLT := he.NewLinearTransformationEvaluator(eval)

	var APermuted *rlwe.Ciphertext
	if APermuted, err = evalLT.EvaluateNew(A, mulParams.PermuteRows); err != nil {
		return nil, fmt.Errorf("[he.LinearTransformationEvaluator].EvaluateNew: %w", err)
	}

	if err = eval.Rescale(APermuted, APermuted); err != nil {
		return nil, fmt.Errorf("[hefloat.Evaluator].Rescale: %w", err)
	}

	var BPermuted *rlwe.Ciphertext
	if BPermuted, err = evalLT.EvaluateNew(B, mulParams.PermuteCols); err != nil {
		return nil, fmt.Errorf("[he.LinearTransformationEvaluator].EvaluateNew: %w", err)
	}

	if err = eval.Rescale(BPermuted, BPermuted); err != nil {
		return nil, fmt.Errorf("[hefloat.Evaluator].Rescale: %w", err)
	}

	// First element of the inner product (without relinearization)
	if err = eval.Mul(APermuted, BPermuted, C); err != nil {
		return nil, fmt.Errorf("[hefloat.Evaluator].Mul: %w", err)
	}

	// Decompose A and B for hoisting linear transforms
	eval.DecomposeNTT(APermuted.Level(), levelP, alpha, APermuted.Q[1], true, bufDecompQPA)
	eval.DecomposeNTT(BPermuted.Level(), levelP, alpha, BPermuted.Q[1], true, bufDecompQPB)

	// Reset pool to the correct level
	bufARescaled, err = rlwe.NewCiphertextAtLevelFromPoly(APermuted.Level()-2, -1, buff.BufARescaled[:], nil)
	if err != nil {
		panic(err)
	}

	*bufARescaled.MetaData = *A.MetaData

	bufBRescaled, err = rlwe.NewCiphertextAtLevelFromPoly(APermuted.Level()-2, -1, buff.BufBRescaled[:], nil)
	if err != nil {
		panic(err)
	}

	*bufBRescaled.MetaData = *B.MetaData

	// Inner product
	for i := range mulParams.Dimensions() - 1 {

		// Row & Cols rotations
		if err = evalLT.MultiplyByDiagMatrix(APermuted, mulParams.RotateCols[i], bufDecompQPA, bufA); err != nil {
			return nil, fmt.Errorf("[he.LinearTransformationEvaluator].MultiplyByDiagMatrix: %w", err)
		}

		if err = eval.Rescale(bufA, bufARescaled); err != nil {
			return nil, fmt.Errorf("[hefloat.Evaluator].Rescale: %w", err)
		}

		// Case where the dimension divides the slots
		if mulParams.RotateRows == nil {

			if err = eval.AutomorphismHoisted(BPermuted, bufDecompQPB, params.GaloisElement((i+1)*mulParams.Dimensions()), bufB); err != nil {
				return nil, fmt.Errorf("[hefloat.Evaluator].AutomorphismHoisted: %w", err)
			}

			if err = eval.ScaleUp(bufB, rlwe.NewScale(rQ.SubRings[bufB.Level()].Modulus), bufB); err != nil {
				return nil, fmt.Errorf("[hefloat.Evaluator].ScaleUp: %w", err)
			}

		} else {
			if err = evalLT.MultiplyByDiagMatrix(BPermuted, mulParams.RotateRows[i], bufDecompQPB, bufB); err != nil {
				return nil, fmt.Errorf("[he.LinearTransformationEvaluator].MultiplyByDiagMatrix: %w", err)
			}
		}

		if err = eval.Rescale(bufB, bufBRescaled); err != nil {
			return nil, fmt.Errorf("[hefloat.Evaluator].Rescale: %w", err)
		}

		if err = eval.MulThenAdd(bufARescaled, bufBRescaled, C); err != nil {
			return nil, fmt.Errorf("[hefloat.Evaluator].MulThenAdd: %w", err)
		}
	}

	if err := eval.Relinearize(C, C); err != nil {
		return nil, fmt.Errorf("[hefloat.Evaluator].Relinearize: %w", err)
	}

	return C, nil
}
