package matrix

import (
	"golang.org/x/exp/maps"

	"github.com/Pro7ech/lattigo/he"
	"github.com/Pro7ech/lattigo/he/hefloat"
	"github.com/Pro7ech/lattigo/rlwe"
)

func (eval *Evaluator) NewTranspose(level, dims int, scaling float64, inputScale, outputScale rlwe.Scale) (*he.LinearTransformation, error) {

	params := eval.Evaluators[0].Parameters()

	diagonals := TransposeDiagonals(params, dims, scaling)

	ltparams := he.LinearTransformationParameters{
		Indexes:       diagonals.Indexes(),
		LevelQ:        level,
		LevelP:        params.MaxLevelP(),
		Scale:         params.GetScalingFactor(inputScale, outputScale, level),
		LogDimensions: params.LogMaxDimensions(),
	}

	lt := he.NewLinearTransformation(params, ltparams)

	return lt, eval.EncodeLinearTransformation(diagonals, lt)
}

func TransposeIndexes(params hefloat.Parameters, dims int) (indexes map[int]bool) {
	slots := params.MaxSlots()
	indexes = map[int]bool{}
	for i := -dims + 1; i < dims; i++ {
		indexes[i*(dims-1)&(slots-1)] = true
	}
	return
}

func TransposeDiagonals(params hefloat.Parameters, dims int, scaling float64) (diags he.Diagonals[float64]) {

	slots := params.MaxSlots()

	diags = he.Diagonals[float64](make(map[int][]float64))

	dsqrt := dims * dims

	// Section 4.1 of eprint/2018/1041
	for i := -dims + 1; i < dims; i++ {

		m := make([]float64, slots)

		if i >= 0 {
			for j := 0; j < dsqrt-i*dims; j = j + dims + 1 {
				m[i+j] = scaling
			}
		} else {
			for j := -i * dims; j < dsqrt; j = j + dims + 1 {
				m[j] = scaling
			}
		}

		for k := dsqrt; k < slots; k = k + dsqrt {
			copy(m[k:], m[:dsqrt])
		}

		diags[i*(dims-1)&(slots-1)] = m
	}

	return
}

func TransposeGaloisElements(params hefloat.Parameters, dims int) (galEls []uint64) {
	ltParams := &he.LinearTransformationParameters{
		Indexes:       maps.Keys(TransposeIndexes(params, dims)),
		LogDimensions: params.LogMaxDimensions(),
	}
	return ltParams.GaloisElements(params)
}
