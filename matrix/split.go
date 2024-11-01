package matrix

import (
	"fmt"

	"gonum.org/v1/gonum/mat"

	"github.com/Pro7ech/lattigo/he"
	"github.com/Pro7ech/lattigo/he/hefloat"
)

func SplitDiagonals(params hefloat.Parameters, rows, cols, split, padd int, scaling float64) (diags he.Diagonals[float64]) {
	return splitPermutation(params, rows, cols, split, padd, scaling).Diagonals(params.LogMaxDimensions())
}

func SplitGaloisElements(params hefloat.Parameters, rows, cols, split, padd int) (galEls []uint64) {
	return splitPermutation(params, rows, cols, split, padd, 1).GaloisElements(params, params.LogMaxDimensions())
}

func splitPermutation(params hefloat.Parameters, rows, cols, split, padd int, scaling float64) (perm he.Permutation[float64]) {
	flatten := split * rows * (cols/split + padd)

	nbmatrices := params.MaxSlots() / flatten

	perm = he.NewPermutation[float64](nbmatrices * rows * cols)

	for d := range nbmatrices {
		for i := range rows {
			for j := range split {
				for k := range cols / split {
					idx := i*cols + j*(cols/split) + k + d*rows*cols
					perm[idx].X = idx
					perm[idx].Y = k + i*(cols/split+padd) + j*(rows*(cols/split+padd)) + d*flatten
					perm[idx].C = scaling
				}
			}
		}
	}

	return
}

func SplitHeads(in *mat.Dense, split int) (out []*mat.Dense) {
	m0 := in.RawMatrix().Data

	rows, cols := in.Dims()

	if cols%split != 0 {
		panic(fmt.Errorf("invalid split: does not divide cols"))
	}

	colsSplit := cols / split

	m1 := make([][]float64, split)
	for i := range m1 {
		m1[i] = make([]float64, rows*colsSplit)
	}

	for i := range rows {
		for j := range colsSplit {
			for k := range split {
				m1[k][i*colsSplit+j] = m0[i*cols+k*colsSplit+j]
			}
		}
	}

	out = make([]*mat.Dense, split)
	for i := range out {
		out[i] = mat.NewDense(rows, colsSplit, m1[i])
	}

	return
}
