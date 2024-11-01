package client

import (
	"encoding/csv"
	"fmt"
	"os"

	"gonum.org/v1/gonum/mat"

	"github.com/Pro7ech/lattigo/he/hefloat"
	"github.com/Pro7ech/lattigo/rlwe"
)

func Decrypt(cts []rlwe.Ciphertext, n, cols int, dec *rlwe.Decryptor, ecd *hefloat.Encoder) (out []*mat.Dense, err error) {
	out = make([]*mat.Dense, n)

	for i := range out {
		out[i] = mat.NewDense(len(cts), cols, make([]float64, len(cts)*cols))
	}

	values := make([]float64, cts[0].Slots())

	for i := range cts {
		if err = ecd.Decode(dec.DecryptNew(&cts[i]), values); err != nil {
			return nil, fmt.Errorf("ecd.Decode: %w", err)
		}

		for j := range out {
			copy(out[j].RawMatrix().Data[i*cols:(i+1)*cols], values[j*cols:(j+1)*cols])
		}
	}

	return
}

func (c *Client) Dump(path string, m []*mat.Dense) (err error) {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	rows, cols := m[0].Dims()

	data := make([]string, rows*cols)

	for i := range m {
		mi := m[i].RawMatrix().Data
		for j, v := range mi {
			data[j] = fmt.Sprintf("%0.16f", v)
		}
		w.Write(data)
	}

	return
}
