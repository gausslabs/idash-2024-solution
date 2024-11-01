package matrix

import (
	"github.com/Pro7ech/lattigo/he"
	"github.com/Pro7ech/lattigo/he/hefloat"

	"golang.org/x/exp/maps"
)

// DivIntCeil returns c = ceil(a/b).
func DivIntCeil(a, b int) (c int) {
	return (a + b - 1) / b
}

func IndexesGaloisElements(params hefloat.Parameters, indexes map[int]bool, naive bool) (galEls []uint64) {
	ltparams := &he.LinearTransformationParameters{
		Indexes:       maps.Keys(indexes),
		LogDimensions: params.LogMaxDimensions(),
	}
	return ltparams.GaloisElements(params)
}
