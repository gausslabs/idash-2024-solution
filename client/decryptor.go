package client

import (
	"gonum.org/v1/gonum/mat"

	"app/lib"
	"app/matrix"

	"github.com/Pro7ech/lattigo/he/hefloat"
	"github.com/Pro7ech/lattigo/rlwe"
)

type Decryptor struct {
	*matrix.Decryptor
}

func NewDecryptor(params hefloat.Parameters, sk *rlwe.SecretKey) *Decryptor {
	return &Decryptor{
		Decryptor: matrix.NewDecryptor(params, sk),
	}
}

func (dec *Decryptor) DecryptNew(cts []rlwe.Ciphertext, rows, cols, padd, matPerCt int) (out []*mat.Dense, err error) {
	return dec.Decryptor.DecryptNew(cts, rows, cols, padd, matPerCt)
}

func (dec *Decryptor) WithKey(sk *rlwe.SecretKey) *Decryptor {
	return &Decryptor{Decryptor: dec.Decryptor.WithKey(sk)}
}

func GetResults(in []*mat.Dense) (out []*mat.Dense) {

	out = make([]*mat.Dense, lib.NbSamples)

	for i := range len(in) / (lib.NbMatPerCtOut * lib.Rows) {

		offset := i * lib.NbMatPerCtOut * lib.Rows

		for j := range lib.Rows {

			for k := range lib.NbMatPerCtOut {

				if offset+j*lib.NbMatPerCtOut+k >= lib.NbSamples {
					return
				}

				out[offset+j*lib.NbMatPerCtOut+k] = in[offset+j+k*lib.Rows]
			}
		}
	}

	return
}
