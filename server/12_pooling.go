package server

import (
	"fmt"

	"app/lib"
	"app/utils"

	"gonum.org/v1/gonum/mat"

	"github.com/Pro7ech/lattigo/rlwe"
)

func (s *Server) PoolingEncrypted(in []rlwe.Ciphertext) (out []rlwe.Ciphertext, err error) {

	if err = utils.LoadWithBench("Load GaloisKeys", func() (err error) {
		s.KeyManager.LoadGaloisKeys(s.PoolingGaloisElements(s.Evaluator.Evaluators[0].Parameters()))
		s.SetKeys(s.KeyManager)
		return
	}); err != nil {
		return
	}

	if err = utils.RunWithBench("Pooling", func() (LevelIn, LevelOut int, LogScaleIn, LogScaleOut float64, err error) {

		eval := s.Evaluator.Evaluators[0]

		params := eval.Parameters()
		slots := params.MaxSlots()

		mask := make([]float64, slots)
		flatten := lib.Rows * lib.Cols
		for i := range slots / flatten {
			for j := range lib.Cols {
				mask[i*flatten+j] = 1 / float64(lib.Rows)
			}
		}

		LevelIn = in[0].Level()
		LogScaleIn = in[0].LogScale()

		out = make([]rlwe.Ciphertext, (len(in)+lib.Rows-1)/lib.Rows)

		hoistingbuffer := eval.NewHoistingBuffer(LevelIn, params.MaxLevelP())

		for i := range out {

			for j := range lib.Rows {

				if i*lib.Rows+j == len(in) {
					break
				}

				ct := &in[i*lib.Rows+j]

				for ct.Level() > 2 {
					eval.DropLevel(ct, 1)
				}

				if err = eval.InnerSum(ct, lib.Cols, lib.Rows, hoistingbuffer, ct); err != nil {
					return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[rlwe.Evaluator][InnerSum]: %w", err)
				}

				if err = eval.Mul(ct, mask, ct); err != nil {
					return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[rlwe.Evaluator][Mul][ct,mask,ct]: %w", err)
				}

				if j == 0 {
					out[i] = *ct
				} else {
					if err = eval.Rotate(ct, -j*lib.Cols, ct); err != nil {
						return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[hefloat.Evaluator][Rotate][in,%d,in]: %w", -i*lib.Cols, err)
					}

					if err = eval.Add(&out[i], ct, &out[i]); err != nil {
						return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[hefloat.Evaluator][Add][out,in[%d],out]: %w", i*lib.Rows+j, err)
					}
				}
			}

			if err = eval.Rescale(&out[i], &out[i]); err != nil {
				return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[hefloat.Evaluator][Rescale][out,out]: %w", err)
			}

		}

		LevelOut = out[0].Level()
		LogScaleOut = out[0].LogScale()

		return

	}); err != nil {
		return nil, err
	}

	return out, nil
}

func (s *Server) PoolingApproximate(in []*mat.Dense) (out []*mat.Dense) {
	return s.PoolingExact(in)
}

func (s *Server) PoolingExact(in []*mat.Dense) (out []*mat.Dense) {
	out = make([]*mat.Dense, len(in))
	rows, cols := in[0].Dims()

	for i := range in {

		m0 := make([]float64, cols)
		m1 := in[i].RawMatrix().Data

		for i := range rows {
			for j := range cols {
				m0[j] += m1[i*cols+j]
			}
		}

		scalign := 1 / float64(rows)

		for i := range cols {
			m0[i] *= scalign
		}

		out[i] = mat.NewDense(1, cols, m0)
	}

	return
}
