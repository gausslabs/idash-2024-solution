package matrix

import (
	"github.com/Pro7ech/lattigo/he"
	"github.com/Pro7ech/lattigo/he/hefloat"

	"golang.org/x/exp/maps"
)

func PermuteRowsDiagonals(params hefloat.Parameters, dims int, scaling float64, transpose bool) (diagonals he.Diagonals[float64]) {
	slots := params.MaxSlots()

	diagonals = he.Diagonals[float64](make(map[int][]float64))

	dsqrt := dims * dims

	// sigma(A)_{i, j} -> A_{i, i+j}, see Section 3.1 of of eprint/2018/1041
	for i := -dims + 1; i < dims; i++ {

		m := make([]float64, slots)

		for j := range (slots / dsqrt) * dsqrt {
			if d := (dsqrt + j - i*dims) % dsqrt; (i < 0 && d < dims && d >= -i) || (i >= 0 && d < dims-i) {
				m[j] = scaling
			}
		}

		diagonals[i&(slots-1)] = m
	}

	if transpose {
		return MulDiags(TransposeDiagonals(params, dims, 1), diagonals)
	}

	return
}

func PermuteRowsIndexes(params hefloat.Parameters, dims int, transpose bool) (indexes map[int]bool) {
	slots := params.MaxSlots()
	indexes = map[int]bool{}
	for i := -dims + 1; i < dims; i++ {
		indexes[i&(slots-1)] = true
	}
	if transpose {
		return MulIndexes(params, TransposeIndexes(params, dims), indexes)
	}
	return
}

func PermuteRowsGaloisElements(params hefloat.Parameters, dims int, transpose bool) (galEls []uint64) {
	ltparams := he.LinearTransformationParameters{
		Indexes:       maps.Keys(PermuteRowsIndexes(params, dims, transpose)),
		LogDimensions: params.LogMaxDimensions(),
	}
	return ltparams.GaloisElements(params)
}
