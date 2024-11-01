package server

import (
	"fmt"

	"app/lib"
	"app/matrix"
	"app/utils"

	"gonum.org/v1/gonum/mat"

	"github.com/Pro7ech/lattigo/he"
	"github.com/Pro7ech/lattigo/rlwe"
)

func (s *Server) QMulKTEncrypted(Q, K, QMulKT []rlwe.Ciphertext) (err error) {

	if err = utils.LoadWithBench("Load GaloisKeys", func() (err error) {
		s.KeyManager.LoadGaloisKeys(s.TransposeGaloisElements(s.Evaluator.Evaluators[0].Parameters()))
		s.SetKeys(s.KeyManager)
		return
	}); err != nil {
		return
	}

	var Transpose *he.LinearTransformation
	if err = utils.LoadWithBench("Load Transpose", func() (err error) {
		Scaling := 1.0
		params := s.Evaluator.Evaluators[0].Parameters()
		Transpose, err = s.NewTranspose(K[0].Level(), lib.Rows, Scaling, K[0].Scale, params.DefaultScale())
		if err != nil {
			panic(fmt.Errorf("[matrix.NewTranspose]: %w", err))
		}
		return
	}); err != nil {
		return
	}

	if err = utils.RunWithBench("K -> K^T", func() (LevelIn, LevelOut int, LogScaleIn, LogScaleOut float64, err error) {

		LevelIn = K[0].Level()
		LogScaleIn = K[0].LogScale()

		if err = s.EvaluateLinearTransformation(K, Transpose, K); err != nil {
			return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[EvaluateLinearTransformation][K,Transpose]: %w", err)
		}

		if err = s.Rescale(K, K); err != nil {
			return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[Rescale][K]: %w", err)
		}

		LevelOut = K[0].Level()
		LogScaleOut = K[0].LogScale()

		return

	}); err != nil {
		return
	}

	if err = utils.LoadWithBench("Load GaloisKeys", func() (err error) {
		s.KeyManager.LoadGaloisKeys(s.QMulKTGaloisElements(s.Evaluator.Evaluators[0].Parameters()))
		s.SetKeys(s.KeyManager)
		return
	}); err != nil {
		return
	}

	var MulParamsQKT *matrix.MulParameters
	if err = utils.LoadWithBench("Load MulParameters", func() (err error) {
		TransposeL := false
		TransposeR := false
		Scaling := lib.KTScaling
		MulParamsQKT, err = s.NewMulParameters(
			min(Q[0].Level(), K[0].Level()),
			Scaling,
			TransposeL,
			TransposeR,
			Q[0].Scale,
			K[0].Scale)
		if err != nil {
			panic(fmt.Errorf("[NewServer][matrix.NewMulParameters]: %w", err))
		}
		return
	}); err != nil {
		return
	}

	if err = utils.RunWithBench("Q x K^T -> QKT", func() (LevelIn, LevelOut int, LogScaleIn, LogScaleOut float64, err error) {

		LevelIn = min(Q[0].Level(), K[0].Level())
		LogScaleIn = (K[0].LogScale() + Q[0].LogScale()) / 2

		if err = s.MulCt(Q, K, MulParamsQKT, QMulKT); err != nil {
			return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[Mul][Q,KT]: %w", err)
		}

		if err = s.Rescale(QMulKT, QMulKT); err != nil {
			return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[Rescale][QMulKT]: %w", err)
		}

		LevelOut = QMulKT[0].Level()
		LogScaleOut = QMulKT[0].LogScale()

		return

	}); err != nil {
		return
	}

	return
}

func (s *Server) QMulKTApproximate(Q, K [][]*mat.Dense) (QKT [][]*mat.Dense) {
	return s.QMulKTExact(Q, K)
}

func (s *Server) QMulKTExact(Q, K [][]*mat.Dense) (QKT [][]*mat.Dense) {
	rows, _ := Q[0][0].Dims()
	split := lib.Split
	scaling := lib.KTScaling
	QKT = make([][]*mat.Dense, len(Q))
	for i := range Q {
		QKT[i] = make([]*mat.Dense, split)
		for j := range split {
			QKT[i][j] = mat.NewDense(rows, rows, make([]float64, rows*rows))
			QKT[i][j].Mul(Q[i][j], K[i][j].T())
			QKT[i][j].Apply(func(i, j int, x float64) (y float64) {
				return x * scaling
			}, QKT[i][j])
		}
	}
	return
}
