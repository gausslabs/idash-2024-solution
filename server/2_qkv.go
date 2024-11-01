package server

import (
	"fmt"

	"app/layers"
	"app/lib"
	"app/matrix"
	"app/utils"
	"app/weights"

	"gonum.org/v1/gonum/mat"

	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils/structs"
)

func (s *Server) QKVEncrypted(in []rlwe.Ciphertext) (Q, K, V []rlwe.Ciphertext, err error) {

	if err = utils.LoadWithBench("Load GaloisKeys", func() (err error) {
		s.KeyManager.LoadGaloisKeys(s.QKVGaloisElements(s.Evaluator.Evaluators[0].Parameters()))
		s.SetKeys(s.KeyManager)
		return
	}); err != nil {
		return
	}

	var KeyWeights *matrix.Plaintext
	var keyB []float64
	if err = utils.LoadWithBench("Load Key Matrix", func() (err error) {
		var keyW *mat.Dense
		keyW, keyB = weights.LoadTransformerBlockKeyWeights(s.path)
		KeyWeights, err = s.EncodeMulNew(keyW, lib.LevelKey)
		return
	}); err != nil {
		return
	}

	K = structs.Vector[rlwe.Ciphertext](in).Clone()

	if err = utils.RunWithBench("In x Key Matrix -> K", func() (LevelIn, LevelOut int, LogScaleIn, LogScaleOut float64, err error) {

		LevelIn = K[0].Level()
		LogScaleIn = K[0].LogScale()

		if err = s.MulPt(K, KeyWeights, K); err != nil {
			return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[MulPt][KeyWeights]: %w", err)
		}

		if err = s.Rescale(K, K); err != nil {
			return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[Rescale][K]: %w", err)
		}

		if err = s.AddPt(K, weights.GetBias(lib.Rows, keyB), K); err != nil {
			return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[AddPt][KeyBias]: %w", err)
		}

		LevelOut = K[0].Level()
		LogScaleOut = K[0].LogScale()

		return

	}); err != nil {
		return
	}

	var QueryWeights *matrix.Plaintext
	var queryB []float64
	if err = utils.LoadWithBench("Load Query Matrix", func() (err error) {
		var queryW *mat.Dense
		queryW, queryB = weights.LoadTransformerBlockQueryWeights(s.path)
		QueryWeights, err = s.EncodeMulNew(queryW, lib.LevelQuery)
		return
	}); err != nil {
		return
	}

	// 3) QKV Linear Layer
	Q = structs.Vector[rlwe.Ciphertext](in).Clone()

	if err = utils.RunWithBench("In x Query Matrix -> Q", func() (LevelIn, LevelOut int, LogScaleIn, LogScaleOut float64, err error) {

		LevelIn = Q[0].Level()
		LogScaleIn = Q[0].LogScale()

		if err = s.MulPt(Q, QueryWeights, Q); err != nil {
			return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[MulPt][QueryWeights]: %w", err)
		}

		if err = s.Rescale(Q, Q); err != nil {
			return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[Rescale][Q]: %w", err)
		}

		if err = s.AddPt(Q, weights.GetBias(lib.Rows, queryB), Q); err != nil {
			return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[AddPt][QueryBias]: %w", err)
		}

		LevelOut = Q[0].Level()
		LogScaleOut = Q[0].LogScale()

		return

	}); err != nil {
		return
	}

	var ValueWeights *matrix.Plaintext
	var valueB []float64
	if err = utils.LoadWithBench("Load Value Matrix", func() (err error) {
		var valueW *mat.Dense
		valueW, valueB = weights.LoadTransformerBlockValueWeights(s.path)
		ValueWeights, err = s.EncodeMulNew(valueW, lib.LevelValue)
		return
	}); err != nil {
		return
	}

	V = structs.Vector[rlwe.Ciphertext](in).Clone()

	if err = utils.RunWithBench("In x Value Matrix -> V", func() (LevelIn, LevelOut int, LogScaleIn, LogScaleOut float64, err error) {

		LevelIn = V[0].Level()
		LogScaleIn = V[0].LogScale()

		if err = s.MulPt(V, ValueWeights, V); err != nil {
			return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[MulPt][ValueWeights]: %w", err)
		}

		if err = s.Rescale(V, V); err != nil {
			return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[Rescale][V]: %w", err)
		}

		if err = s.AddPt(V, weights.GetBias(lib.Rows, valueB), V); err != nil {
			return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[AddPt][ValueBias]: %w", err)
		}

		LevelOut = V[0].Level()
		LogScaleOut = V[0].LogScale()

		return

	}); err != nil {
		return
	}

	return
}

func (s *Server) QKVApproximate(in []*mat.Dense) (Q, K, V []*mat.Dense) {
	return s.QKVExact(in)
}

func (s *Server) QKVExact(in []*mat.Dense) (Q, K, V []*mat.Dense) {

	valueW, valueB := weights.LoadTransformerBlockValueWeights(s.path)
	keyW, keyB := weights.LoadTransformerBlockKeyWeights(s.path)
	queryW, queryB := weights.LoadTransformerBlockQueryWeights(s.path)

	QueryDense := layers.NewDense(queryW, queryB)
	KeyDense := layers.NewDense(keyW, keyB)
	ValueDense := layers.NewDense(valueW, valueB)

	rows, _ := in[0].Dims()
	_, colsQ := QueryDense.Weights.Dims()
	_, colsK := KeyDense.Weights.Dims()
	_, colsV := ValueDense.Weights.Dims()

	Q = make([]*mat.Dense, len(in))
	K = make([]*mat.Dense, len(in))
	V = make([]*mat.Dense, len(in))

	for i := range in {
		Q[i] = mat.NewDense(rows, colsQ, make([]float64, rows*colsQ))
		QueryDense.Evaluate(in[i], Q[i])

		K[i] = mat.NewDense(rows, colsK, make([]float64, rows*colsK))
		KeyDense.Evaluate(in[i], K[i])

		V[i] = mat.NewDense(rows, colsV, make([]float64, rows*colsV))
		ValueDense.Evaluate(in[i], V[i])
	}
	return
}
