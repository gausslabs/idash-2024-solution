package client

import (
	"testing"

	"gonum.org/v1/gonum/mat"

	"github.com/Pro7ech/lattigo/he/hefloat"
	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils/sampling"

	"github.com/stretchr/testify/require"
)

func TestClient(t *testing.T) {

	params, err := hefloat.NewParametersFromLiteral(hefloat.ParametersLiteral{
		LogN:            15,
		LogQ:            []int{60, 45, 45, 45},
		LogP:            []int{60},
		LogDefaultScale: 45,
		RingType:        ring.ConjugateInvariant,
	})
	require.NoError(t, err)

	sk := rlwe.NewKeyGenerator(params).GenSecretKeyNew()

	ecd := hefloat.NewEncoder(params)

	enc := NewEncryptor(params, sk)
	dec := NewDecryptor(params, sk)

	rows := 4
	cols := 1
	a := 1.0
	b := 0.0
	replicate := 12

	n := 4

	r := sampling.NewSource([32]byte{})

	in := make([]*mat.Dense, n)
	for i := range in {
		m := make([]float64, rows*cols)
		for j := range m {
			m[j] = r.Float64(-0.1, 0.1)
		}
		in[i] = mat.NewDense(rows, cols, m)
	}

	t.Run("Encryption&Decryption", func(t *testing.T) {

		ct, err := enc.EncryptNew(in, replicate, a, b)
		require.NoError(t, err)

		want := make([]*mat.Dense, n)
		for i := range want {
			want[i] = mat.NewDense(rows, replicate, make([]float64, rows*replicate))
			duplicateColumns(in[i], want[i], a, b)
		}

		have, err := dec.DecryptNew(ct, rows, replicate)
		require.NoError(t, err)

		for i := range n {
			hefloat.VerifyTestVectors(params, ecd, nil, have[i].RawMatrix().Data, want[i].RawMatrix().Data, params.LogDefaultScale(), 0, true, t)
		}
	})
}
