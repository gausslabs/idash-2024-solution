package matrix

import (
	"fmt"

	"gonum.org/v1/gonum/mat"

	"github.com/Pro7ech/lattigo/he/hefloat"
	"github.com/Pro7ech/lattigo/rlwe"
)

type Encryptor struct {
	*rlwe.Encryptor
	*hefloat.Encoder
}

func NewEncryptor(params hefloat.Parameters, sk *rlwe.SecretKey) (enc *Encryptor) {
	return &Encryptor{
		Encryptor: rlwe.NewEncryptor(params, sk),
		Encoder:   hefloat.NewEncoder(params),
	}
}

func (enc *Encryptor) WithKey(sk *rlwe.SecretKey) *Encryptor {
	return &Encryptor{Encryptor: enc.Encryptor.WithKey(sk), Encoder: enc.Encoder}
}

func (enc *Encryptor) EncryptNew(in []*mat.Dense, padd, matPerCt int) (cts []rlwe.Ciphertext, err error) {

	rows, cols := in[0].Dims()

	flattened := rows * (cols + padd)

	params := enc.Parameters()

	slots := params.MaxSlots()

	cts = make([]rlwe.Ciphertext, DivIntCeil(len(in), matPerCt))

	pt := hefloat.NewPlaintext(params, params.MaxLevel())

	for i := range cts {

		values := make([]float64, slots)

		for j := range matPerCt {

			if i*matPerCt+j == len(in) {
				break
			}

			m1 := values[flattened*j:]
			m0 := in[i*matPerCt+j].RawMatrix().Data

			for k := range rows {
				copy(m1[k*(cols+padd):], m0[k*cols:(k+1)*cols])
			}
		}

		ct := hefloat.NewCiphertext(params, 1, params.MaxLevel())

		if enc.Encode(values, pt); err != nil {
			return nil, fmt.Errorf("[hefloat.Encoder].Encode: %w", err)
		}

		if err = enc.Encryptor.Encrypt(pt, ct); err != nil {
			return nil, fmt.Errorf("[rlwe.Encryptor].Encrypt: %w", err)
		}

		cts[i] = *ct
	}

	return
}
