package client

import (
	"gonum.org/v1/gonum/mat"

	"app/matrix"

	"github.com/Pro7ech/lattigo/he/hefloat"
	"github.com/Pro7ech/lattigo/rlwe"
)

type Encryptor struct {
	*matrix.Encryptor
}

func NewEncryptor(params hefloat.Parameters, sk *rlwe.SecretKey) *Encryptor {
	return &Encryptor{
		Encryptor: matrix.NewEncryptor(params, sk),
	}
}

func (enc *Encryptor) WithKey(sk *rlwe.SecretKey) *Encryptor {
	return &Encryptor{Encryptor: enc.Encryptor.WithKey(sk)}
}

func (enc *Encryptor) EncryptNew(in []*mat.Dense, padd, matPerCt int) (cts []rlwe.Ciphertext, err error) {
	return enc.Encryptor.EncryptNew(in, padd, matPerCt)
}
