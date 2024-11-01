package matrix

import (
	"fmt"

	"gonum.org/v1/gonum/mat"

	"github.com/Pro7ech/lattigo/utils/concurrency"

	"github.com/Pro7ech/lattigo/he"
	"github.com/Pro7ech/lattigo/he/hefloat"
	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils"
)

func (eval *Evaluator) NewLinearTransformation(level int, scaleIn, scaleOut rlwe.Scale, naive bool, diagonals he.Diagonals[float64]) (*he.LinearTransformation, error) {

	params := eval.Evaluators[0].Parameters()

	ltparams := he.LinearTransformationParameters{
		Indexes:       diagonals.Indexes(),
		LevelQ:        level,
		LevelP:        params.MaxLevelP(),
		Scale:         params.GetScalingFactor(scaleIn, scaleOut, level),
		LogDimensions: params.LogMaxDimensions(),
	}

	if naive {
		ltparams.GiantStep = -1
	}

	lt := he.NewLinearTransformation(params, ltparams)
	return lt, eval.EncodeLinearTransformation(diagonals, lt)
}

// EncodeLinearTransformation encodes on a pre-allocated LinearTransformation a set of non-zero diagonaes of a matrix representing a linear transformation.
func (eval *Evaluator) EncodeLinearTransformation(diagonals he.Diagonals[float64], allocated *he.LinearTransformation) (err error) {

	ecds := make([]*hefloat.Encoder, len(eval.Evaluators))
	for i := range ecds {
		ecds[i] = eval.Evaluators[i].Encoder
	}

	rows := 1 << allocated.LogDimensions.Rows
	cols := 1 << allocated.LogDimensions.Cols
	GiantStep := allocated.GiantStep

	diags := diagonals.Indexes()

	metaData := allocated.MetaData

	metaData.Scale = allocated.Scale

	type encoder struct {
		*hefloat.Encoder
		buff []float64
	}

	encoders := make([]*encoder, len(eval.Evaluators))
	for i := range encoders {
		encoders[i] = new(encoder)
		encoders[i].Encoder = eval.Evaluators[i].Encoder
		encoders[i].buff = make([]float64, rows*cols)
	}

	m := concurrency.NewRessourceManager(encoders)

	if GiantStep <= 0 {
		for _, i := range diags {

			m.Run(func(ecd *encoder) (err error) {

				var v []float64

				idx := i
				if idx < 0 {
					idx += cols
				}

				if vec, ok := allocated.Vec[idx]; !ok {
					return fmt.Errorf("cannot EncodeLinearTransformation: error encoding on LinearTransformation: plaintext diagonal [%d] does not exist", idx)
				} else {

					if v, err = diagonals.At(i, cols); err != nil {
						return fmt.Errorf("cannot EncodeLinearTransformation: %w", err)
					}

					if err = ecd.Embed(v, metaData, vec); err != nil {
						return
					}
				}

				return

			})
		}
	} else {

		index, _, _ := allocated.BSGSIndex()

		for j := range index {

			rot := -j & (cols - 1)

			for _, i := range index[j] {

				m.Run(func(ecd *encoder) (err error) {

					var v []float64

					if vec, ok := allocated.Vec[i+j]; !ok {
						return fmt.Errorf("cannot Encode: error encoding on LinearTransformation BSGS: input does not match the same non-zero diagonals")
					} else {

						if v, err = diagonals.At(i+j, cols); err != nil {
							return fmt.Errorf("cannot EncodeLinearTransformation: %w", err)
						}

						if err = ecd.Embed(rotateDiagonal(v, rot, metaData, ecd.buff), metaData, vec); err != nil {
							return
						}
					}

					return
				})
			}
		}
	}

	return m.Wait()
}

func rotateDiagonal[T any](v []T, rot int, metaData *rlwe.MetaData, buf []T) (values []T) {

	rows := 1 << metaData.LogDimensions.Rows
	cols := 1 << metaData.LogDimensions.Cols

	rot &= (cols - 1)

	if rot != 0 {

		values = buf

		for i := 0; i < rows; i++ {
			utils.RotateSliceAllocFree(v[i*cols:(i+1)*cols], rot, values[i*cols:(i+1)*cols])
		}

	} else {
		values = v
	}

	return
}

func MulIndexes(params hefloat.Parameters, A, B map[int]bool) (C map[int]bool) {
	slots := params.MaxSlots()
	C = map[int]bool{}
	for i := range A {
		for j := range B {
			C[(i+j)&(slots-1)] = true
		}
	}
	return
}

func Diagonalize(w *mat.Dense, replicate, slots int) (diagonals he.Diagonals[float64]) {

	rows, cols := w.Dims()

	if rows != cols {
		panic("matrix must be square")
	}

	diagonals = he.Diagonals[float64](map[int][]float64{})

	mask := slots - 1

	wT := w.T()

	for i := -rows + 1; i < rows; i++ {

		m := make([]float64, slots)

		if i >= 0 {
			for j := 0; j < rows-i; j++ {
				m[j] = wT.At(j, j+i)
			}
		} else {
			for j := 0; j < rows+i; j++ {
				m[j] = wT.At(j-i, j)
			}
			utils.RotateSliceAllocFree(m, i, m)
		}

		for j := 1; j < replicate; j++ {
			copy(m[j*rows:], m[:rows])
		}

		diagonals[i&mask] = m
	}

	return
}

func AddDiagonals(A he.Diagonals[float64], i int, B []float64) {
	if Ai, ok := A[i]; ok {
		add(Ai, B, Ai)
	} else {
		A[i] = clone(B)
	}
}

func DiagonalizeIndexes(rows, cols int) (indexes map[int]bool) {
	indexes = map[int]bool{}
	for i := -rows; i < cols; i++ {
		indexes[i] = true
	}
	return
}

func DiagonalizeGaloisElements(params hefloat.Parameters, dims int) (galEls []uint64) {
	return IndexesGaloisElements(params, DiagonalizeIndexes(dims, dims), false)
}

// MulDiags evaluates A <- A x B and returns A.
func MulDiags(A, B he.Diagonals[float64]) he.Diagonals[float64] {
	var buff []float64
	for i := range A {
		buff = make([]float64, len(A[i]))
		break
	}
	A.Mul(B, buff, add, rot, mul, clone)
	return A
}

func add(a, b, c []float64) {
	for i := range a {
		c[i] = a[i] + b[i]
	}
}

func clone(a []float64) (b []float64) {
	b = make([]float64, len(a))
	copy(b, a)
	return
}

func rot(a []float64, k int, b []float64) {
	utils.RotateSliceAllocFree(a, k, b)
}

func mul(a, b, c []float64) {
	for i := range a {
		c[i] = a[i] * b[i]
	}
}
