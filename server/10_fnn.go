package server

import (
	"app/lib"
	"app/matrix"
	"app/matrix/relu"
	"app/utils"
	"app/weights"
	"fmt"

	"github.com/Pro7ech/lattigo/he"
	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils/structs"

	"gonum.org/v1/gonum/mat"
)

func (s *Server) FNNEncrypted(in []rlwe.Ciphertext, btp he.Bootstrapper[rlwe.Ciphertext]) (err error) {

	if err = utils.LoadWithBench("Load GaloisKeys", func() (err error) {
		s.KeyManager.LoadGaloisKeys(s.FNNGaloisElements(s.Evaluator.Evaluators[0].Parameters()))
		s.SetKeys(s.KeyManager)
		return
	}); err != nil {
		return
	}

	fnn1W, fnn1B, fnn2W, fnn2B := weights.LoadTransformerBlockFNNWeights(s.path)

	scale := max(lib.ReLUParameters.AbsMax)

	fnn1W.Scale(1/scale, fnn1W)
	fnn2W.Scale(scale, fnn2W)

	fnn1WSplit := matrix.SplitHeads(fnn1W, 2)

	rowsFNN2, colsFNN2 := fnn2W.Dims()

	fnn2WSplit := [2]*mat.Dense{
		mat.NewDense(rowsFNN2/2, colsFNN2, fnn2W.RawMatrix().Data[:(rowsFNN2/2)*colsFNN2]),
		mat.NewDense(rowsFNN2/2, colsFNN2, fnn2W.RawMatrix().Data[(rowsFNN2/2)*colsFNN2:]),
	}

	FNN1Bias := [2]*mat.Dense{weights.GetBias(lib.Rows, fnn1B[:lib.Cols]), weights.GetBias(lib.Rows, fnn1B[lib.Cols:])}
	FNN2Bias := weights.GetBias(lib.Rows, fnn2B)

	FNN1Bias[0].Scale(1/scale, FNN1Bias[0])
	FNN1Bias[1].Scale(1/scale, FNN1Bias[1])

	eval := relu.NewEvaluator(lib.ReLUParameters, s.Evaluator, btp)

	acc := structs.Vector[rlwe.Ciphertext](in).Clone()

	for i := range 2 {

		var FNN1W *he.LinearTransformation
		if err = utils.LoadWithBench(fmt.Sprintf("FNN: Load FNN1[%d]", i), func() (err error) {
			params := s.Evaluator.Evaluators[0].Parameters()
			FNN1W, err = s.NewLinearTransformation(
				in[0].Level(),
				in[0].Scale,
				params.DefaultScale(),
				false,
				matrix.Diagonalize(fnn1WSplit[i], params.MaxSlots()/lib.Cols, params.MaxSlots()))
			return
		}); err != nil {
			return
		}

		fnn := structs.Vector[rlwe.Ciphertext](in).Clone()

		if err = utils.RunWithBench(fmt.Sprintf("FNN: In x FNN1W[%d] + FNN1B[%d] -> fnn%d", i, i, i), func() (LevelIn, LevelOut int, LogScaleIn, LogScaleOut float64, err error) {

			LevelIn = in[0].Level()
			LogScaleIn = in[0].LogScale()

			if err = s.EvaluateLinearTransformation(in, FNN1W, fnn); err != nil {
				return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[MulPt][fnn,FNN1W[%d],fnn]: %w", i, err)
			}

			if err = s.Rescale(fnn, fnn); err != nil {
				return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[Rescale][fnn,fnn]: %w", err)
			}

			if err = s.AddPt(fnn, FNN1Bias[i], fnn); err != nil {
				return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[AddPt][fnn,s.FNN1Bias[%d],fnn]: %w", i, err)
			}

			LevelOut = fnn[0].Level()
			LogScaleOut = fnn[0].LogScale()

			return

		}); err != nil {
			return
		}

		if err = utils.RunWithBench(fmt.Sprintf("FNN: ReLU(fnn%d) -> fnn%d", i, i), func() (LevelIn, LevelOut int, LogScaleIn, LogScaleOut float64, err error) {

			LevelIn = fnn[0].Level()
			LogScaleIn = fnn[0].LogScale()

			if err = eval.EvaluateEncrypted(fnn); err != nil {
				return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[relu.Evaluator][EvaluateEncrypted][fnn]: %w", err)
			}

			LevelOut = fnn[0].Level()
			LogScaleOut = fnn[0].LogScale()

			return

		}); err != nil {
			return
		}

		var FNN2W *he.LinearTransformation
		if err = utils.LoadWithBench(fmt.Sprintf("FNN: Load FNN2[%d]", i), func() (err error) {
			params := s.Evaluator.Evaluators[0].Parameters()
			FNN2W, err = eval.NewLinearTransformation(
				fnn[0].Level(),
				fnn[0].Scale,
				params.DefaultScale(),
				false,
				matrix.Diagonalize(fnn2WSplit[i], params.MaxSlots()/lib.Cols, params.MaxSlots()))
			return
			return
		}); err != nil {
			return
		}

		if err = utils.RunWithBench(fmt.Sprintf("FNN: fnn%d x FNN2[%d] -> acc", i, i), func() (LevelIn, LevelOut int, LogScaleIn, LogScaleOut float64, err error) {

			LevelIn = fnn[0].Level()
			LogScaleIn = fnn[0].LogScale()

			if err = s.EvaluateLinearTransformation(fnn, FNN2W, fnn); err != nil {
				return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[MulPt][fnn,FNN2W[%d],fnn]: %w", i, err)
			}

			if err = s.Rescale(fnn, fnn); err != nil {
				return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[Rescale][fnn,fnn]: %w", err)
			}

			if err = s.AddCt(acc, fnn, acc); err != nil {
				return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[AddCt][acc,fnn,acc]: %w", err)
			}

			LevelOut = acc[0].Level()
			LogScaleOut = acc[0].LogScale()

			return

		}); err != nil {
			return
		}
	}

	if err = utils.RunWithBench("FNN: acc + FNN2B -> In", func() (LevelIn, LevelOut int, LogScaleIn, LogScaleOut float64, err error) {

		LevelIn = min(acc[0].Level(), in[0].Level())
		LogScaleIn = (acc[0].LogScale() + in[0].LogScale()) / 2

		if err = s.AddPt(acc, FNN2Bias, in); err != nil {
			return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[AddPt][in,FNN2Bias,in]: %w", err)
		}

		LevelOut = in[0].Level()
		LogScaleOut = in[0].LogScale()

		return

	}); err != nil {
		return
	}
	return
}

func (s *Server) FNNApproximate(in []*mat.Dense) {
	eval := relu.NewEvaluator(lib.ReLUParameters, nil, nil)
	s.fnn(in, eval.EvaluateApproximate)
}

func (s *Server) FNNExact(in []*mat.Dense) {
	eval := relu.NewEvaluator(lib.ReLUParameters, nil, nil)
	s.fnn(in, eval.EvaluateExact)
}

func (s *Server) fnn(in []*mat.Dense, f func(in, out []*mat.Dense)) {

	scale := max(lib.ReLUParameters.AbsMax)

	FNN1W, fnn1B, FNN2W, fnn2B := weights.LoadTransformerBlockFNNWeights(s.path)
	FNN1B := utils.BiasToDense(lib.Rows, fnn1B)

	FNN1W.Scale(1/scale, FNN1W)
	FNN1B.Scale(1/scale, FNN1B)
	FNN2W.Scale(scale, FNN2W)

	FNN1WSplit := matrix.SplitHeads(FNN1W, 2)
	FNN1BSplit := matrix.SplitHeads(FNN1B, 2)

	rowsFNN2, colsFNN2 := FNN2W.Dims()

	FNN2WSplit := [2]*mat.Dense{
		mat.NewDense(rowsFNN2/2, colsFNN2, FNN2W.RawMatrix().Data[:(rowsFNN2/2)*colsFNN2]),
		mat.NewDense(rowsFNN2/2, colsFNN2, FNN2W.RawMatrix().Data[(rowsFNN2/2)*colsFNN2:]),
	}

	FNN2B := utils.BiasToDense(lib.Rows, fnn2B)

	_, colsFNN1 := FNN1WSplit[0].Dims()
	rowsFNN2, colsFNN2 = FNN2WSplit[0].Dims()

	rows, _ := in[0].Dims()

	nn1 := mat.NewDense(rows, colsFNN2, make([]float64, rows*colsFNN2))
	nn0 := make([]*mat.Dense, len(in))
	for i := range nn0 {
		nn0[i] = mat.NewDense(rows, colsFNN1, make([]float64, rows*colsFNN1))
	}

	acc := make([]*mat.Dense, len(in))
	for i := range acc {
		acc[i] = mat.NewDense(rows, colsFNN2, make([]float64, rows*colsFNN2))
	}

	for i := range 2 {

		fnn1W := FNN1WSplit[i]
		fnn1B := FNN1BSplit[i]

		for j := range in {
			nn0[j].Mul(in[j], fnn1W)
			nn0[j].Add(nn0[j], fnn1B)
		}

		f(nn0, nn0)

		fnn2W := FNN2WSplit[i]

		for j := range in {
			nn1.Mul(nn0[j], fnn2W)
			acc[j].Add(acc[j], nn1)
		}
	}

	for i := range in {
		in[i].Add(in[i], acc[i])
		in[i].Add(in[i], FNN2B)
	}

	return
}
