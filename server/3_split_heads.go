package server

import (
	"fmt"
	"slices"

	"app/lib"
	"app/matrix"
	"app/utils"

	"gonum.org/v1/gonum/mat"

	"github.com/Pro7ech/lattigo/he"
	"github.com/Pro7ech/lattigo/rlwe"
)

func (s *Server) SplitHeadsEncrypted(Q, K, V []rlwe.Ciphertext) (err error) {

	if err = utils.LoadWithBench("Load GaloisKeys", func() (err error) {
		s.KeyManager.LoadGaloisKeys(s.SplitHeadsGaloisElements(s.Evaluator.Evaluators[0].Parameters()))
		s.SetKeys(s.KeyManager)
		return
	}); err != nil {
		return
	}

	var SplitHeads *he.LinearTransformation
	if err = utils.LoadWithBench("Load Split Heads", func() (err error) {
		params := s.Evaluator.Evaluators[0].Parameters()
		SplitHeads, err = s.NewLinearTransformation(
			slices.Max([]int{Q[0].Level(), K[0].Level(), V[0].Level()}),
			params.DefaultScale(),
			params.DefaultScale(),
			false,
			matrix.SplitDiagonals(params, lib.Rows, lib.Cols, lib.Split, lib.Padding, 1.0))
		return
	}); err != nil {
		return
	}

	if err = utils.RunWithBench("Split Heads Q", func() (LevelIn, LevelOut int, LogScaleIn, LogScaleOut float64, err error) {

		LevelIn = Q[0].Level()
		LogScaleIn = Q[0].LogScale()

		if err = s.EvaluateLinearTransformation(Q, SplitHeads, Q); err != nil {
			return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[SplitHeads][Q]: %w", err)
		}

		if err = s.Rescale(Q, Q); err != nil {
			return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[Rescale][Q]: %w", err)
		}

		LevelOut = Q[0].Level()
		LogScaleOut = Q[0].LogScale()

		return

	}); err != nil {
		return
	}

	if err = utils.RunWithBench("Split Heads K", func() (LevelIn, LevelOut int, LogScaleIn, LogScaleOut float64, err error) {

		LevelIn = K[0].Level()
		LogScaleIn = K[0].LogScale()

		if err = s.EvaluateLinearTransformation(K, SplitHeads, K); err != nil {
			return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[SplitHeads][K]: %w", err)
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

	if err = utils.RunWithBench("Split Heads V", func() (LevelIn, LevelOut int, LogScaleIn, LogScaleOut float64, err error) {

		LevelIn = V[0].Level()
		LogScaleIn = V[0].LogScale()

		if err = s.EvaluateLinearTransformation(V, SplitHeads, V); err != nil {
			return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[SplitHeads][V]: %w", err)
		}

		if err = s.Rescale(V, V); err != nil {
			return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[Rescale][V]: %w", err)
		}

		LevelOut = V[0].Level()
		LogScaleOut = V[0].LogScale()

		return

	}); err != nil {
		return
	}

	return
}

func (s *Server) SplitHeadsApproximate(Q, K, V []*mat.Dense) (QSplit, KSPlit, VSplit [][]*mat.Dense) {
	return s.SplitHeadsExact(Q, K, V)
}

func (s *Server) SplitHeadsExact(Q, K, V []*mat.Dense) (QSplit, KSPlit, VSplit [][]*mat.Dense) {
	QSplit = make([][]*mat.Dense, len(Q))
	for i := range QSplit {
		QSplit[i] = matrix.SplitHeads(Q[i], lib.Split)
	}

	KSPlit = make([][]*mat.Dense, len(K))
	for i := range KSPlit {
		KSPlit[i] = matrix.SplitHeads(K[i], lib.Split)
	}

	VSplit = make([][]*mat.Dense, len(V))
	for i := range VSplit {
		VSplit[i] = matrix.SplitHeads(V[i], lib.Split)
	}

	return
}
