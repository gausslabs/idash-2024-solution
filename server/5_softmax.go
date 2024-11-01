package server

import (
	"fmt"

	"app/lib"
	"app/matrix/softmax"
	"app/utils"

	"gonum.org/v1/gonum/mat"

	"github.com/Pro7ech/lattigo/he"
	"github.com/Pro7ech/lattigo/rlwe"
)

func (s *Server) SoftMaxEncrypted(QKT []rlwe.Ciphertext, btp he.Bootstrapper[rlwe.Ciphertext]) (err error) {

	if err = utils.LoadWithBench("Load GaloisKeys", func() (err error) {
		s.KeyManager.LoadGaloisKeys(s.SoftMaxGaloisElements(s.Evaluator.Evaluators[0].Parameters()))
		s.SetKeys(s.KeyManager)
		return
	}); err != nil {
		return
	}

	eval := softmax.NewEvaluator(lib.SoftMaxParameters, s.Evaluator, btp)
	if err = eval.EvaluateEncrypted(QKT); err != nil {
		return fmt.Errorf("[softmax.Evaluator][EvaluateEncrypted]: %w", err)
	}
	return
}

func (s *Server) SoftMaxExact(QKT [][]*mat.Dense) {
	eval := softmax.NewEvaluator(lib.SoftMaxParameters, nil, nil)
	m := utils.Flatten(QKT)
	eval.EvaluateExact(m, m)
}

func (s *Server) SoftMaxApproximate(QKT [][]*mat.Dense) (StatsIn, StatsExp, StatsNorm utils.Stats) {
	eval := softmax.NewEvaluator(lib.SoftMaxParameters, nil, nil)
	m := utils.Flatten(QKT)
	return eval.EvaluateApproximate(m, m)
}
