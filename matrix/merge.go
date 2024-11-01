package matrix

import (
	"gonum.org/v1/gonum/mat"

	"github.com/Pro7ech/lattigo/he"
	"github.com/Pro7ech/lattigo/he/hefloat"
)

func MergeDiagonals(params hefloat.Parameters, rows, cols, split, padd int, scaling float64) (perm he.Diagonals[float64]) {
	return mergePermutation(params, rows, cols, split, padd, scaling).Diagonals(params.LogMaxDimensions())
}

func MergeIndexes(params hefloat.Parameters, rows, cols, split, padd int) (indexes []int) {
	return mergePermutation(params, rows, cols, split, padd, 1).Indexes(params.LogMaxDimensions())
}

func MergeGaloisElements(params hefloat.Parameters, rows, cols, split, padd int) (galEls []uint64) {
	return mergePermutation(params, rows, cols, split, padd, 1).GaloisElements(params, params.LogMaxDimensions())
}

func mergePermutation(params hefloat.Parameters, rows, cols, split, padd int, scaling float64) (perm he.Permutation[float64]) {
	flatten := split * rows * (cols/split + padd)

	nbmatrices := params.MaxSlots() / flatten

	perm = he.NewPermutation[float64](nbmatrices * rows * cols)

	for d := range nbmatrices {
		for i := range rows {
			for j := range split {
				for k := range cols / split {
					idx := i*cols + j*(cols/split) + k + d*rows*cols
					perm[idx].X = k + i*(cols/split+padd) + j*(rows*(cols/split+padd)) + d*flatten
					perm[idx].Y = idx
					perm[idx].C = scaling
				}
			}
		}
	}
	return perm
}

func MergeHeads(in []*mat.Dense) (out *mat.Dense) {

	rows, cols := in[0].Dims()

	colsMerge := cols * len(in)

	m0 := make([][]float64, len(in))
	for i := range m0 {
		m0[i] = in[i].RawMatrix().Data
	}

	m1 := make([]float64, rows*colsMerge)

	for i := range rows {
		for j := range cols {
			for k := range len(in) {
				m1[i*colsMerge+k*cols+j] = m0[k][i*cols+j]
			}
		}
	}

	return mat.NewDense(rows, colsMerge, m1)
}
