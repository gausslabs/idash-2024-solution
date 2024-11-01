package matrix

import (
	"gonum.org/v1/gonum/mat"

	"github.com/Pro7ech/lattigo/he"
)

func (eval *Evaluator) EncodeMulNew(w *mat.Dense, level int) (pt *Plaintext, err error) {

	params := eval.Evaluators[0].Parameters()
	slots := params.MaxSlots()

	rows, _ := w.Dims()
	replicate := slots / rows

	diagonals := Diagonalize(w, replicate, slots)

	ltparams := he.LinearTransformationParameters{
		Indexes:       diagonals.Indexes(),
		LevelQ:        level,
		LevelP:        params.MaxLevelP(),
		Scale:         params.GetScalingFactor(params.DefaultScale(), params.DefaultScale(), level),
		LogDimensions: params.LogMaxDimensions(),
	}

	lt := he.NewLinearTransformation(params, ltparams)

	return &Plaintext{lt}, eval.EncodeLinearTransformation(diagonals, lt)
}

func Flatten(in *mat.Dense, slots int) (values []float64) {

	rows, cols := in.Dims()

	flattened := rows * cols

	matperct := slots / flattened

	values = make([]float64, slots)
	for j := range matperct {
		copy(values[flattened*j:], in.RawMatrix().Data)
	}

	return
}
