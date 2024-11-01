package server

import (
	"fmt"
	"math"

	"gonum.org/v1/gonum/mat"

	"github.com/Pro7ech/lattigo/utils/concurrency"
	"app/lib"
	"app/utils"
	"app/weights"

	"github.com/Pro7ech/lattigo/he"
	"github.com/Pro7ech/lattigo/he/hefloat"
	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils/bignum"
)

func (s *Server) EmbedExact(in []*mat.Dense) (out []*mat.Dense) {

	lut := weights.LoadEmbeddingLUT(s.path)

	out = make([]*mat.Dense, len(in))

	for i := range in {

		m0 := in[i].RawMatrix().Data
		m1 := mat.NewDense(lib.Rows, lib.Cols, make([]float64, lib.Rows*lib.Cols))

		for i := range lib.Rows {
			x := int(math.Round((m0[i*lib.Cols]-lib.B)/lib.A)) + 1 // +1 because 0 is skipped
			m1.SetRow(i, lut.RawRowView(x))
		}

		out[i] = m1
	}

	return
}

func (s *Server) EmbedApproximate(in []*mat.Dense) (out []*mat.Dense) {

	coeffs, err := utils.ReadFile(s.path+"/embedding_coefficients.csv", ',', 0, false, lib.NumCPU)
	if err != nil {
		panic(fmt.Errorf("utils.ReadFile: %w", err))
	}

	out = make([]*mat.Dense, len(in))

	for k := range in {
		data := make([]float64, lib.Rows*lib.Cols)

		m := in[k].RawMatrix().Data

		for i := range lib.Rows {
			offset := i * lib.Cols
			for j := range lib.Cols {
				data[j+offset] = utils.ChebEval(coeffs[j], -1, 1, m[j+offset])
			}
		}

		out[k] = mat.NewDense(lib.Rows, lib.Cols, data)
	}

	return
}

func (s *Server) EmbedEncrypted(in []rlwe.Ciphertext) (out []rlwe.Ciphertext, err error) {

	params := s.Evaluator.Evaluators[0].Parameters()
	ecd := s.Evaluator.Evaluators[0].Encoder
	slots := params.MaxSlots()

	var polyVec *he.PolynomialVector
	var polyVecEncoded *he.EncodedPolynomialVector
	if err = utils.LoadWithBench("Load Polynomials", func() (err error) {
		if polyVec, err = GetEmbeddingPolynmials(s.path, lib.Rows, slots); err != nil {
			return fmt.Errorf("[GetEmbeddingPolynmials]: %w", err)
		}

		if polyVecEncoded, err = hefloat.GetEncodedPolynomialVector(params, ecd, polyVec, in[0].Level(), in[0].Scale, params.DefaultScale()); err != nil {
			return fmt.Errorf("[GetEncodedPolynomialVector]: %w", err)
		}

		return
	}); err != nil {
		return
	}

	out = make([]rlwe.Ciphertext, len(in))

	return out, utils.RunWithBench("Poly(In)", func() (LevelIn, LevelOut int, LogScaleIn, LogScaleOut float64, err error) {

		LevelIn = in[0].Level()
		LogScaleIn = in[0].LogScale()

		m := concurrency.NewRessourceManager[*hefloat.Evaluator](s.Evaluator.Evaluators)

		for i := range out {
			m.Run(func(eval *hefloat.Evaluator) (err error) {
				var ct *rlwe.Ciphertext
				evalPoly := hefloat.NewPolynomialEvaluator(params, eval)
				if ct, err = polyVecEncoded.Evaluate(evalPoly, &in[i]); err != nil {
					return fmt.Errorf("[he.EncodedPolynomialVector][Evaluate]: %w", err)
				}
				out[i] = *ct
				return
			})
		}

		if err = m.Wait(); err != nil {
			return LevelIn, LevelOut, LogScaleIn, LogScaleOut, err
		}

		if err = s.Rescale(out, out); err != nil {
			return LevelIn, LevelOut, LogScaleIn, LogScaleOut, err
		}

		LevelOut = out[0].Level()
		LogScaleOut = out[0].LogScale()
		return
	})
}

func GetEmbeddingPolynmials(path string, rows, slots int) (polyVec *he.PolynomialVector, err error) {

	cols := lib.Cols

	coeffs, err := utils.ReadFile(path+"/embedding_coefficients.csv", ',', 0, false, lib.NumCPU)
	if err != nil {
		panic(fmt.Errorf("utils.ReadFile: %w", err))
	}

	polys := map[int]*he.Polynomial{}

	for i := range cols {
		polys[i] = he.NewPolynomial(bignum.NewPolynomial(bignum.Chebyshev, coeffs[i], [2]float64{-lib.K, lib.K}))
	}

	nbMatPerCt := slots / (rows * cols)

	mapping := make([]int, rows*cols*nbMatPerCt)

	for k := range nbMatPerCt {
		offset := k * rows * cols
		for i := range rows {
			for j := range cols {
				mapping[offset+i*cols+j] = j
			}
		}
	}

	return he.NewPolynomialVector(polys, mapping)
}
