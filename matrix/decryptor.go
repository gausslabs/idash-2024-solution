package matrix

import (
	"fmt"

	"gonum.org/v1/gonum/mat"

	"github.com/Pro7ech/lattigo/he/hefloat"
	"github.com/Pro7ech/lattigo/rlwe"
)

type Decryptor struct {
	*rlwe.Decryptor
	*hefloat.Encoder
}

func NewDecryptor(params hefloat.Parameters, sk *rlwe.SecretKey) (dec *Decryptor) {
	return &Decryptor{
		Decryptor: rlwe.NewDecryptor(params, sk),
		Encoder:   hefloat.NewEncoder(params),
	}
}

func (dec *Decryptor) WithKey(sk *rlwe.SecretKey) *Decryptor {
	return &Decryptor{Decryptor: dec.Decryptor.WithKey(sk), Encoder: dec.Encoder}
}

func (dec *Decryptor) DecryptNew(cts []rlwe.Ciphertext, rows, cols, padd, matPerCt int) (out []*mat.Dense, err error) {

	params := dec.Parameters()

	slots := params.MaxSlots()

	flattened := rows * (cols + padd)

	out = make([]*mat.Dense, matPerCt*len(cts))

	values := make([]float64, slots)
	pt := hefloat.NewPlaintext(params, cts[0].Level())

	for i := range cts {

		dec.Decryptor.Decrypt(&cts[i], pt)

		if err = dec.Decode(pt, values); err != nil {
			return nil, fmt.Errorf("[hefloat.Encoder].Decode: %w", err)
		}

		for j := range matPerCt {

			m0 := values[j*flattened:]
			m1 := make([]float64, rows*cols)

			for k := range rows {
				copy(m1[k*cols:(k+1)*cols], m0[k*(cols+padd):k*(cols+padd)+cols])
			}

			out[i*matPerCt+j] = mat.NewDense(rows, cols, m1)
		}
	}

	return
}
