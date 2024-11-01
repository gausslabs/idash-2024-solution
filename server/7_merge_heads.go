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

func (s *Server) MergeHeadsEncrypted(QKTMulVSplit []rlwe.Ciphertext) (err error) {

	if err = utils.LoadWithBench("Load GaloisKeys", func() (err error) {
		s.KeyManager.LoadGaloisKeys(s.MergeHeadsGaloisElements(s.Evaluator.Evaluators[0].Parameters()))
		s.SetKeys(s.KeyManager)
		return
	}); err != nil {
		return
	}

	var MergeHeads *he.LinearTransformation
	if err = utils.LoadWithBench("Load Merge Heads", func() (err error) {
		params := s.Evaluator.Evaluators[0].Parameters()
		MergeHeads, err = s.NewLinearTransformation(
			QKTMulVSplit[0].Level(),
			QKTMulVSplit[0].Scale,
			params.DefaultScale(),
			false,
			matrix.MergeDiagonals(params, lib.Rows, lib.Cols, lib.Split, lib.Padding, 1.0))
		return
	}); err != nil {
		return
	}

	if err = utils.RunWithBench("Merge Heads QKTV", func() (LevelIn, LevelOut int, LogScaleIn, LogScaleOut float64, err error) {

		LevelIn = QKTMulVSplit[0].Level()
		LogScaleIn = QKTMulVSplit[0].LogScale()

		if err = s.EvaluateLinearTransformation(QKTMulVSplit, MergeHeads, QKTMulVSplit); err != nil {
			return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[MergeHeads][Q]: %w", err)
		}

		if err = s.Rescale(QKTMulVSplit, QKTMulVSplit); err != nil {
			return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[Rescale][Q]: %w", err)
		}

		LevelOut = QKTMulVSplit[0].Level()
		LogScaleOut = QKTMulVSplit[0].LogScale()

		return

	}); err != nil {
		return
	}

	return
}

func (s *Server) MergeHeadsApproximate(QKTSplit [][]*mat.Dense) (QKTMerged []*mat.Dense) {
	return s.MergeHeadsExact(QKTSplit)
}

func (s *Server) MergeHeadsExact(QKTSplit [][]*mat.Dense) (QKTMerged []*mat.Dense) {
	QKTMerged = make([]*mat.Dense, len(QKTSplit))
	for i := range QKTSplit {
		QKTMerged[i] = matrix.MergeHeads(QKTSplit[i])
	}
	return
}
