package matrix

import (
	"github.com/Pro7ech/lattigo/he"
	"github.com/Pro7ech/lattigo/he/hefloat"
	"github.com/Pro7ech/lattigo/utils"

	"golang.org/x/exp/maps"
)

func RotateRowsIndexes(params hefloat.Parameters, dims, k int) (indexes map[int]bool) {
	k %= dims
	indexes = map[int]bool{}
	slots := params.MaxSlots()
	if dims < slots {
		indexes[slots-dims+k] = true
		indexes[k] = true
	}
	return
}

func RotateRowsDiagonals(params hefloat.Parameters, dims, k int) (diagonals he.Diagonals[float64]) {

	k %= dims

	diagonals = he.Diagonals[float64](make(map[int][]float64))

	slots := params.MaxSlots()

	dL := make([]float64, slots)
	for i := range slots / dims {
		for j := 0; j < k; j++ {
			dL[i*dims+j] = 1
		}
	}
	idx := (k - dims) & (slots - 1)
	utils.RotateSliceInPlace(dL, idx)
	diagonals[idx] = dL

	dR := make([]float64, slots)
	for i := range slots / dims {
		for j := k; j < dims; j++ {
			dR[i*dims+j] = 1
		}
	}
	diagonals[k] = dR
	utils.RotateSliceInPlace(dR, k)

	return
}

func RotateRowsGaloisElements(params hefloat.Parameters, dims, k int) (galEls []uint64) {
	ltparams := he.LinearTransformationParameters{
		Indexes:       maps.Keys(RotateRowsIndexes(params, dims, k)),
		LogDimensions: params.LogMaxDimensions(),
		GiantStep:         -1,
	}
	return ltparams.GaloisElements(params)
}
