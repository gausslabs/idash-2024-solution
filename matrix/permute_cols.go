package matrix

import (
	"fmt"

	"github.com/Pro7ech/lattigo/he"
	"github.com/Pro7ech/lattigo/he/hefloat"

	"golang.org/x/exp/maps"
)

func PermuteColsDiagonals(params hefloat.Parameters, dims int, scaling float64, transpose bool) (diagonals he.Diagonals[float64]) {

	slots := params.MaxSlots()

	diagonals = he.Diagonals[float64](make(map[int][]float64))

	dsqrt := dims * dims

	// tau(A)_{i, j} -> A_{i+j,j}, see Section 3.1 of of eprint/2018/1041
	if dsqrt < slots {

		for i := -dims + 1; i < dims; i++ {

			m := make([]float64, slots)

			if i >= 0 {
				for j := 0; j < dims-i; j++ {
					m[j*dims+i] = scaling
				}
			} else {
				for j := 0; j < dims+i; j++ {
					m[(j-i+1)*dims+i] = scaling
				}
			}

			for j := dsqrt; j < slots; j = j + dsqrt {
				copy(m[j:], m[:dsqrt])
			}

			diagonals[(i*dims)&(slots-1)] = m

		}
	} else if dsqrt == slots {
		for i := range dims {

			m := make([]float64, slots)

			for j := 0; j < dims; j++ {
				m[j*dims+i] = scaling
			}

			for j := dsqrt; j < slots; j = j + dsqrt {
				copy(m[j:], m[:dsqrt])
			}

			diagonals[i*dims] = m
		}
	} else {
		panic(fmt.Errorf("dims * dims = %d cannot be greater than slots = %d", dsqrt, slots))
	}

	if transpose {
		diagonals = MulDiags(TransposeDiagonals(params, dims, 1), diagonals)
	}

	return
}

func PermuteColsIndexes(params hefloat.Parameters, dims int, transpose bool) (indexes map[int]bool) {
	slots := params.MaxSlots()
	indexes = map[int]bool{}
	dsqrt := dims * dims
	if dsqrt < slots {
		for i := -(dims - 1) * dims; i < dsqrt; i = i + dims {
			indexes[(i+slots)&(slots-1)] = true
		}
	} else {
		for i := 0; i < dims; i++ {
			indexes[i*dims] = true
		}
	}

	if transpose {
		indexes = MulIndexes(params, TransposeIndexes(params, dims), indexes)
	}

	return
}

func PermuteColsGaloisElements(params hefloat.Parameters, dims int, transpose bool) (galEls []uint64) {
	ltparams := he.LinearTransformationParameters{
		Indexes:       maps.Keys(PermuteColsIndexes(params, dims, transpose)),
		LogDimensions: params.LogMaxDimensions(),
	}
	return ltparams.GaloisElements(params)
}
