package client

import (
	"fmt"
	"math/rand/v2"

	"app/lib"
	"app/tokenizer"

	"gonum.org/v1/gonum/mat"
)

func (c *Client) Load(path string, start, end int) (X []*mat.Dense, Y []float64, err error) {
	vocabulary := map[string]float64{}
	for i, v := range tokenizer.Vocabulary {
		vocabulary[i] = v*lib.A + lib.B
	}

	if X, Y, err = tokenizer.Load(path, lib.Rows, vocabulary); err != nil {
		return nil, nil, fmt.Errorf("[tokenizer][Load]: %w", err)
	}

	X = X[start:end]

	for i := range X {
		X[i] = ColVecToMatrix(X[i], lib.Cols)
	}

	return X, Y, nil
}

func (c *Client) LoadFuzzy(n int) (out []*mat.Dense, err error) {
	vocabulary := make([]float64, tokenizer.VocabularySize)
	var i int
	for _, v := range tokenizer.Vocabulary {
		vocabulary[i] = v*lib.A + lib.B
		i++
	}

	out = make([]*mat.Dense, n)

	size := len(vocabulary)

	m := make([]float64, lib.Rows)
	for i := range out {
		for j := range m {
			m[j] = vocabulary[rand.IntN(size)]
		}
		out[i] = ColVecToMatrix(mat.NewDense(lib.Rows, 1, m), lib.Cols)
	}

	return
}

func (c *Client) LoadSynthetic(path string, n int) (out []*mat.Dense, err error) {

	var data []*mat.Dense
	if data, _, err = tokenizer.Load(path, lib.Rows, tokenizer.Vocabulary); err != nil {
		return nil, fmt.Errorf("[tokenizer][Load]: %w", err)
	}

	features := make([]map[int]int, lib.Rows)
	for i := range features {
		features[i] = map[int]int{}
	}

	for i := range data {
		for j, c := range data[i].RawMatrix().Data {
			features[j][int(c)] += 1
		}
	}

	table := make([][]float64, lib.Rows)

	for i := range features {
		m := make([]float64, len(data))
		var idx int

		for j, c := range features[i] {
			for k := 0; k < c; k++ {
				m[idx+k] = float64(j)*lib.A + lib.B
			}
			idx += c
		}

		table[i] = m
	}

	out = make([]*mat.Dense, n)

	m := make([]float64, lib.Rows)
	for i := range out {
		for j := range m {
			m[j] = table[j][rand.IntN(tokenizer.VocabularySize)]
		}
		out[i] = ColVecToMatrix(mat.NewDense(lib.Rows, 1, m), lib.Cols)
	}

	return
}

func ColVecToMatrix(in *mat.Dense, cols int) (out *mat.Dense) {

	rows, _ := in.Dims()

	out = mat.NewDense(rows, cols, make([]float64, rows*cols))

	rawIn := in.RawMatrix().Data
	rawOut := out.RawMatrix().Data

	for i, c := range rawIn {
		m := rawOut[i*cols:]
		for j := range cols {
			m[j] = c
		}
	}

	return
}
