package server

import (
	"slices"

	"app/keys"
	"app/lib"
	"app/matrix"
	"app/matrix/normalization"
	"app/matrix/softmax"

	"golang.org/x/exp/maps"

	"github.com/Pro7ech/lattigo/he/hefloat"
	"github.com/Pro7ech/lattigo/rlwe"
)

type Server struct {
	KeyManager       *keys.Manager
	EvaluationKeySet rlwe.EvaluationKeySet
	*matrix.Evaluator
	*matrix.MulParameters
	path  string
	Sk    *rlwe.SecretKey
	Debug bool
}

func NewServer(path string, threads int) *Server {
	params := lib.NewParameters()

	evaluators := make([]*hefloat.Evaluator, threads)
	evaluators[0] = hefloat.NewEvaluator(params, nil)
	for i := range threads - 1 {
		evaluators[i+1] = evaluators[0].ShallowCopy()
	}

	return &Server{
		Evaluator: matrix.NewEvaluator(params, lib.Rows, evaluators),
		path:      path,
	}
}

func (s *Server) GaloisElements(params hefloat.Parameters) (galEls []uint64, maxconcurrentkeys int) {

	m := map[uint64]bool{}

	galEls = matrix.MulParametersGaloisElements(params, lib.Rows, false, false)
	maxconcurrentkeys = max(maxconcurrentkeys, len(galEls))
	for _, galEl := range galEls {
		m[galEl] = true
	}

	galEls = matrix.TransposeGaloisElements(params, lib.Rows)
	maxconcurrentkeys = max(maxconcurrentkeys, len(galEls))
	for _, galEl := range galEls {
		m[galEl] = true
	}

	galEls = matrix.DiagonalizeGaloisElements(params, lib.Cols)
	maxconcurrentkeys = max(maxconcurrentkeys, len(galEls))
	for _, galEl := range galEls {
		m[galEl] = true
	}

	galEls = matrix.MergeGaloisElements(params, lib.Rows, lib.Cols, lib.Split, lib.Padding)
	maxconcurrentkeys = max(maxconcurrentkeys, len(galEls))
	for _, galEl := range galEls {
		m[galEl] = true
	}

	galEls = matrix.SplitGaloisElements(params, lib.Rows, lib.Cols, lib.Split, lib.Padding)
	maxconcurrentkeys = max(maxconcurrentkeys, len(galEls))
	for _, galEl := range galEls {
		m[galEl] = true
	}

	galEls = normalization.GaloisElements(params, lib.Cols)
	maxconcurrentkeys = max(maxconcurrentkeys, len(galEls))
	for _, galEl := range galEls {
		m[galEl] = true
	}

	galEls = softmax.GaloisElements(params, lib.Rows, lib.NumCts)
	maxconcurrentkeys = max(maxconcurrentkeys, len(galEls))
	for _, galEL := range galEls {
		m[galEL] = true
	}

	galEls = rlwe.GaloisElementsForInnerSum(params, lib.Cols, lib.Rows)
	maxconcurrentkeys = max(maxconcurrentkeys, len(galEls))
	for _, galEL := range galEls {
		m[galEL] = true
	}

	for i := 1; i < (lib.NbSamples+lib.NbMatPerCtIn-1)/lib.NbMatPerCtIn; i++ {
		m[params.GaloisElement(-i*lib.Cols)] = true
	}

	galEls = maps.Keys(m)
	slices.Sort(galEls)

	return
}

func (s *Server) SetKeyManager(km *keys.Manager) {
	s.KeyManager = km
	s.Evaluator.SetKeys(km)
}

func (s *Server) QKVGaloisElements(params hefloat.Parameters) (galEls []uint64) {
	m := map[uint64]bool{}
	for _, galEl := range matrix.DiagonalizeGaloisElements(params, lib.Cols) {
		m[galEl] = true
	}
	galEls = maps.Keys(m)
	slices.Sort(galEls)
	return
}

func (s *Server) SplitHeadsGaloisElements(params hefloat.Parameters) (galEls []uint64) {
	m := map[uint64]bool{}
	for _, galEl := range matrix.SplitGaloisElements(params, lib.Rows, lib.Cols, lib.Split, lib.Padding) {
		m[galEl] = true
	}
	galEls = maps.Keys(m)
	slices.Sort(galEls)
	return
}

func (s *Server) TransposeGaloisElements(params hefloat.Parameters) (galEls []uint64) {
	m := map[uint64]bool{}
	for _, galEl := range matrix.TransposeGaloisElements(params, lib.Rows) {
		m[galEl] = true
	}
	galEls = maps.Keys(m)
	slices.Sort(galEls)
	return
}

func (s *Server) QMulKTGaloisElements(params hefloat.Parameters) (galEls []uint64) {
	m := map[uint64]bool{}
	for _, galEl := range matrix.MulParametersGaloisElements(params, lib.Rows, false, false) {
		m[galEl] = true
	}
	galEls = maps.Keys(m)
	slices.Sort(galEls)
	return
}

func (s *Server) SoftMaxGaloisElements(params hefloat.Parameters) (galEls []uint64) {
	m := map[uint64]bool{}
	for _, galEl := range softmax.GaloisElements(params, lib.Rows, lib.NumCts) {
		m[galEl] = true
	}
	galEls = maps.Keys(m)
	slices.Sort(galEls)
	return
}

func (s *Server) QMulKTMulVGaloisElements(params hefloat.Parameters) (galEls []uint64) {
	m := map[uint64]bool{}
	for _, galEl := range matrix.MulParametersGaloisElements(params, lib.Rows, false, false) {
		m[galEl] = true
	}
	galEls = maps.Keys(m)
	slices.Sort(galEls)
	return
}

func (s *Server) MergeHeadsGaloisElements(params hefloat.Parameters) (galEls []uint64) {
	m := map[uint64]bool{}
	for _, galEl := range matrix.MergeGaloisElements(params, lib.Rows, lib.Cols, lib.Split, lib.Padding) {
		m[galEl] = true
	}
	galEls = maps.Keys(m)
	slices.Sort(galEls)
	return
}

func (s *Server) CombineGaloisElements(params hefloat.Parameters) (galEls []uint64) {
	m := map[uint64]bool{}
	for _, galEl := range matrix.DiagonalizeGaloisElements(params, lib.Cols) {
		m[galEl] = true
	}
	galEls = maps.Keys(m)
	slices.Sort(galEls)
	return
}

func (s *Server) NormalizationGaloisElements(params hefloat.Parameters) (galEls []uint64) {
	m := map[uint64]bool{}
	for _, galEl := range normalization.GaloisElements(params, lib.Cols) {
		m[galEl] = true
	}
	galEls = maps.Keys(m)
	slices.Sort(galEls)
	return
}

func (s *Server) FNNGaloisElements(params hefloat.Parameters) (galEls []uint64) {
	m := map[uint64]bool{}
	for _, galEl := range matrix.DiagonalizeGaloisElements(params, lib.Cols) {
		m[galEl] = true
	}
	galEls = maps.Keys(m)
	slices.Sort(galEls)
	return
}

func (s *Server) PoolingGaloisElements(params hefloat.Parameters) (galEls []uint64) {
	m := map[uint64]bool{}
	for _, galEL := range rlwe.GaloisElementsForInnerSum(params, lib.Cols, lib.Rows) {
		m[galEL] = true
	}
	for i := 1; i < (lib.NbSamples+lib.NbMatPerCtIn-1)/lib.NbMatPerCtIn; i++ {
		m[params.GaloisElement(-i*lib.Cols)] = true
	}
	galEls = maps.Keys(m)
	slices.Sort(galEls)
	return
}

func (s *Server) ClassifierGaloisElements(params hefloat.Parameters) (galEls []uint64) {
	m := map[uint64]bool{}
	for _, galEl := range matrix.DiagonalizeGaloisElements(params, lib.Cols) {
		m[galEl] = true
	}
	galEls = maps.Keys(m)
	slices.Sort(galEls)
	return
}
