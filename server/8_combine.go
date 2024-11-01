package server

import (
	"fmt"

	"app/layers"
	"app/lib"
	"app/matrix"
	"app/utils"
	"app/weights"

	"gonum.org/v1/gonum/mat"

	"github.com/Pro7ech/lattigo/he"
	"github.com/Pro7ech/lattigo/rlwe"
)

func (s *Server) CombineEncrypted(in, QKTMulV []rlwe.Ciphertext) (err error) {

	if err = utils.LoadWithBench("Load GaloisKeys", func() (err error) {
		s.KeyManager.LoadGaloisKeys(s.CombineGaloisElements(s.Evaluator.Evaluators[0].Parameters()))
		s.SetKeys(s.KeyManager)
		return
	}); err != nil {
		return
	}

	var CombineWeights *he.LinearTransformation
	var combineB []float64
	if err = utils.LoadWithBench("Load Combine", func() (err error) {
		var combineW *mat.Dense
		combineW, combineB = weights.LoadTransformerBlockCombineWeights(s.path)
		params := s.Evaluator.Evaluators[0].Parameters()
		CombineWeights, err = s.NewLinearTransformation(
			min(in[0].Level()+1, QKTMulV[0].Level()),
			QKTMulV[0].Scale,
			params.DefaultScale(),
			false,
			matrix.Diagonalize(combineW, params.MaxSlots()/lib.Cols, params.MaxSlots()))
		return
	}); err != nil {
		return
	}

	if err = utils.RunWithBench("Combine (QKTV, In) -> In", func() (LevelIn, LevelOut int, LogScaleIn, LogScaleOut float64, err error) {

		LevelIn = QKTMulV[0].Level()
		LogScaleIn = QKTMulV[0].LogScale()

		if err = s.EvaluateLinearTransformation(QKTMulV, CombineWeights, QKTMulV); err != nil {
			return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[MulPt][QKTMulV,s.CombineWeights,QKTMulV]: %w", err)
		}

		if err = s.AddPt(QKTMulV, weights.GetBias(lib.Rows, combineB), QKTMulV); err != nil {
			return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[AddPt][QKTMulV, CombineBias]: %w", err)
		}

		if err = s.Rescale(QKTMulV, QKTMulV); err != nil {
			return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[Rescale][QKTMulV]: %w", err)
		}

		if err = s.AddCt(in, QKTMulV, in); err != nil {
			return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[AddCt][in,QKTMulV,in]: %w", err)
		}

		LevelOut = in[0].Level()
		LogScaleOut = in[0].LogScale()

		return

	}); err != nil {
		return
	}
	return
}

func (s *Server) CombineApproximate(in, QKT []*mat.Dense) {
	s.CombineExact(in, QKT)
}

func (s *Server) CombineExact(in, QKT []*mat.Dense) {

	combineW, combineB := weights.LoadTransformerBlockCombineWeights(s.path)
	CombineDense := layers.NewDense(combineW, combineB)

	for i := range QKT {
		CombineDense.Evaluate(QKT[i], QKT[i])
	}

	for i := range in {
		in[i].Add(in[i], QKT[i])
	}
}
