package server

import (
	"fmt"

	"app/matrix"
	"app/utils"

	"gonum.org/v1/gonum/mat"

	"github.com/Pro7ech/lattigo/he"
	"github.com/Pro7ech/lattigo/rlwe"
)

func (s *Server) QKTMulVEncrypted(QKT, V, QKTMulV []rlwe.Ciphertext, btp he.Bootstrapper[rlwe.Ciphertext]) (err error) {

	if err = utils.LoadWithBench("Load GaloisKeys", func() (err error) {
		s.KeyManager.LoadGaloisKeys(s.QMulKTMulVGaloisElements(s.Evaluator.Evaluators[0].Parameters()))
		s.SetKeys(s.KeyManager)
		return
	}); err != nil {
		return
	}

	var MulParamsQKTV *matrix.MulParameters
	if err = utils.LoadWithBench("Load MulParameters", func() (err error) {
		TransposeL := false
		TransposeR := false
		Scaling := 1.0
		MulParamsQKTV, err = s.NewMulParameters(
			min(QKT[0].Level(), V[0].Level()),
			Scaling,
			TransposeL,
			TransposeR,
			QKT[0].Scale,
			V[0].Scale)
		if err != nil {
			panic(fmt.Errorf("[NewServer][matrix.NewMulParameters]: %w", err))
		}
		return
	}); err != nil {
		return
	}

	if err = utils.RunWithBench("QKT x V -> QKTV", func() (LevelIn, LevelOut int, LogScaleIn, LogScaleOut float64, err error) {

		LevelIn = min(QKT[0].Level(), V[0].Level())
		LogScaleIn = (QKT[0].LogScale() + V[0].LogScale()) / 2

		if err = s.MulCt(QKT, V, MulParamsQKTV, QKTMulV); err != nil {
			return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[Mul][QKT,V]: %w", err)
		}

		if err = s.Rescale(QKTMulV, QKTMulV); err != nil {
			return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[Rescale][QKTMulV]: %w", err)
		}

		LevelOut = QKTMulV[0].Level()
		LogScaleOut = QKTMulV[0].LogScale()

		return

	}); err != nil {
		return
	}

	return
}

func (s *Server) QKTMulVApproximate(QKT, V [][]*mat.Dense) (QKTV [][]*mat.Dense) {
	return s.QKTMulVExact(QKT, V)
}

func (s *Server) QKTMulVExact(QKT, V [][]*mat.Dense) (QKTV [][]*mat.Dense) {
	rows, _ := QKT[0][0].Dims()
	_, cols := V[0][0].Dims()
	QKTV = make([][]*mat.Dense, len(QKT))
	for i := range QKT {
		QKTV[i] = make([]*mat.Dense, len(QKT[i]))
		for j := range QKT[i] {
			QKTV[i][j] = mat.NewDense(rows, cols, make([]float64, rows*cols))
			QKTV[i][j].Mul(QKT[i][j], V[i][j])
		}
	}
	return
}
