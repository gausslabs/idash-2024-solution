package server

import (
	"app/lib"
	"app/matrix/normalization"
	"app/utils"
	"app/weights"

	"gonum.org/v1/gonum/mat"

	"github.com/Pro7ech/lattigo/he"
	"github.com/Pro7ech/lattigo/rlwe"
)

func (s *Server) Norm1Encrypted(in []rlwe.Ciphertext, btp he.Bootstrapper[rlwe.Ciphertext]) (err error) {

	if err = utils.LoadWithBench("Load GaloisKeys", func() (err error) {
		s.KeyManager.LoadGaloisKeys(s.NormalizationGaloisElements(s.Evaluator.Evaluators[0].Parameters()))
		s.SetKeys(s.KeyManager)
		return
	}); err != nil {
		return
	}

	gamma, beta := weights.LoadTransformerBlockNorm1Weights(s.path)
	params := lib.Norm1Parameters
	params.Gamma = gamma
	params.Beta = beta
	eval := normalization.NewEvaluator(params, s.Evaluator, btp)
	return eval.EvaluateEncrypted(in, lib.Cols)
}

func (s *Server) Norm1Approximate(in []*mat.Dense) (Min, Max float64) {
	gamma, beta := weights.LoadTransformerBlockNorm1Weights(s.path)
	params := lib.Norm1Parameters
	params.Gamma = gamma
	params.Beta = beta
	eval := normalization.NewEvaluator(params, nil, nil)

	Min = 1e300
	Max = -Min

	for i := range in {
		xMin, xMax := eval.EvaluateApproximate(in[i], in[i])
		Min = min(Min, xMin)
		Max = max(Max, xMax)
	}

	return
}

func (s *Server) Norm1Exact(in []*mat.Dense) (Min, Max float64) {
	gamma, beta := weights.LoadTransformerBlockNorm1Weights(s.path)
	params := lib.Norm1Parameters
	params.Gamma = gamma
	params.Beta = beta
	eval := normalization.NewEvaluator(params, nil, nil)

	Min = 1e300
	Max = -Min

	for i := range in {
		xMin, xMax := eval.EvaluateExact(in[i], in[i])
		Min = min(Min, xMin)
		Max = max(Max, xMax)
	}

	return
}
