package matrix

import (
	"flag"
	"fmt"
	"testing"
	"time"

	"gonum.org/v1/gonum/mat"

	"app/gofhe/he/hefloat"
	"app/gofhe/ring"
	"app/gofhe/rlwe"
	"app/gofhe/utils/sampling"

	"github.com/stretchr/testify/require"
)

var printPrecisionStats = flag.Bool("print-precision", false, "print precision stats")

var paramsInsecure = hefloat.ParametersLiteral{
	LogN:            10,
	LogQ:            []int{60, 45, 45, 45},
	LogP:            []int{60},
	LogDefaultScale: 45,
	RingType:        ring.ConjugateInvariant,
}

type testContext struct {
	kgen *rlwe.KeyGenerator
	sk   *rlwe.SecretKey
	ecd  *hefloat.Encoder
	enc  *rlwe.Encryptor
	dec  *rlwe.Decryptor
	eval *hefloat.Evaluator
}

func newTestContext(params hefloat.Parameters) (tc *testContext) {
	kgen := rlwe.NewKeyGenerator(params)
	sk := kgen.GenSecretKeyNew()
	return &testContext{
		kgen: kgen,
		sk:   sk,
		ecd:  hefloat.NewEncoder(params),
		enc:  rlwe.NewEncryptor(params, sk),
		dec:  rlwe.NewDecryptor(params, sk),
		eval: hefloat.NewEvaluator(params, nil),
	}
}

func TestMatrices(t *testing.T) {

	params, err := hefloat.NewParametersFromLiteral(paramsInsecure)
	require.NoError(t, err)
	tc := newTestContext(params)

	ecd := tc.ecd

	enc := NewEncryptor(params, tc.sk)
	dec := NewDecryptor(params, tc.sk)

	t.Run("Ct+Pt", func(t *testing.T) {

		rows := 25
		cols := 39

		matPerCt := params.MaxSlots() / (rows * cols)

		n := 2

		r := sampling.NewSource([32]byte{})

		in := make([]*mat.Dense, n)
		for i := range in {
			m := make([]float64, rows*cols)
			for j := range m {
				m[j] = r.Float64(-0.1, 0.1)
			}
			in[i] = mat.NewDense(rows, cols, m)
		}

		w := mat.NewDense(rows, cols, make([]float64, rows*cols))
		for j := range rows * cols {
			w.RawMatrix().Data[j] = r.Float64(-0.1, 0.1)
		}

		ct, err := enc.EncryptNew(in[:n], 0, matPerCt)
		require.NoError(t, err)

		eval := NewEvaluator(params, rows, tc.eval)

		now := time.Now()
		require.NoError(t, eval.AddPt(ct, w, ct))
		fmt.Println(time.Since(now))

		have, err := dec.DecryptNew(ct, rows, cols, 0, matPerCt)
		require.NoError(t, err)

		want := mat.NewDense(rows, cols, make([]float64, rows*cols))
		for i := range n {
			want.Add(in[i], w)
			hefloat.VerifyTestVectors(params, tc.ecd, nil, have[i].RawMatrix().Data, want.RawMatrix().Data, params.LogDefaultScale(), 0, *printPrecisionStats, t)
		}
	})

	t.Run("CtxCt", func(t *testing.T) {

		rows := 25

		matPerCt := params.MaxSlots() / (rows * rows)

		mulParams, err := NewMulParameters(params, rows, params.MaxLevel(), 1, false, false, ecd)

		require.NoError(t, err)

		galEls := mulParams.GaloisElements(params)

		rlk := tc.kgen.GenRelinearizationKeyNew(tc.sk)
		gks := tc.kgen.GenGaloisKeysNew(galEls, tc.sk)

		eval := NewEvaluator(params, rows, tc.eval.WithKey(rlwe.NewMemEvaluationKeySet(rlk, gks...)))

		n := 4

		r := sampling.NewSource([32]byte{})

		in := make([]*mat.Dense, n)
		for i := range in {
			m := make([]float64, rows*rows)
			for j := range m {
				m[j] = r.Float64(-0.1, 0.1)
			}
			in[i] = mat.NewDense(rows, rows, m)
		}

		w := make([]*mat.Dense, n)
		for i := range w {
			m := make([]float64, rows*rows)
			for j := range m {
				m[j] = r.Float64(-0.1, 0.1)
			}
			w[i] = mat.NewDense(rows, rows, m)
		}

		ct0, err := enc.EncryptNew(in[:n], 0, matPerCt)
		require.NoError(t, err)

		ct1, err := enc.EncryptNew(w[:n], 0, matPerCt)
		require.NoError(t, err)

		now := time.Now()
		require.NoError(t, eval.MulCt(ct0, ct1, mulParams, ct0))
		eval.Rescale(ct0, ct0)
		fmt.Println(time.Since(now))

		have, err := dec.DecryptNew(ct0, rows, rows, 0, matPerCt)
		require.NoError(t, err)

		want := mat.NewDense(rows, rows, make([]float64, rows*rows))
		for i := range n {
			want.Mul(in[i], w[i])
			hefloat.VerifyTestVectors(params, tc.ecd, nil, have[i].RawMatrix().Data, want.RawMatrix().Data, params.LogDefaultScale(), 0, *printPrecisionStats, t)
		}
	})

	t.Run("CtxCtT", func(t *testing.T) {

		rows := 5

		matPerCt := params.MaxSlots() / (rows * rows)

		mulParams, err := NewMulParameters(params, rows, params.MaxLevel(), 1, false, true, ecd)

		require.NoError(t, err)

		galEls := mulParams.GaloisElements(params)
		galEls = MulParametersGaloisElements(params, rows, false, true)

		rlk := tc.kgen.GenRelinearizationKeyNew(tc.sk)
		gks := tc.kgen.GenGaloisKeysNew(galEls, tc.sk)

		eval := NewEvaluator(params, rows, tc.eval.WithKey(rlwe.NewMemEvaluationKeySet(rlk, gks...)))

		n := 4

		r := sampling.NewSource([32]byte{})

		in := make([]*mat.Dense, n)
		for i := range in {
			m := make([]float64, rows*rows)
			for j := range m {
				m[j] = r.Float64(-0.1, 0.1)
			}
			in[i] = mat.NewDense(rows, rows, m)
		}

		w := make([]*mat.Dense, n)
		for i := range w {
			m := make([]float64, rows*rows)
			for j := range m {
				m[j] = r.Float64(-0.1, 0.1)
			}
			w[i] = mat.NewDense(rows, rows, m)
		}

		ct0, err := enc.EncryptNew(in[:n], 0, matPerCt)
		require.NoError(t, err)

		ct1, err := enc.EncryptNew(w[:n], 0, matPerCt)
		require.NoError(t, err)

		now := time.Now()
		require.NoError(t, eval.MulCt(ct0, ct1, mulParams, ct0))
		eval.Rescale(ct0, ct0)
		fmt.Println(time.Since(now))

		have, err := dec.DecryptNew(ct0, rows, rows, 0, matPerCt)
		require.NoError(t, err)

		want := mat.NewDense(rows, rows, make([]float64, rows*rows))
		for i := range n {
			want.Mul(in[i], w[i].T())
			hefloat.VerifyTestVectors(params, tc.ecd, nil, have[i].RawMatrix().Data, want.RawMatrix().Data, params.LogDefaultScale(), 0, *printPrecisionStats, t)
		}
	})

	t.Run("CtTxCt", func(t *testing.T) {

		rows := 5

		matPerCt := params.MaxSlots() / (rows * rows)

		mulParams, err := NewMulParameters(params, rows, params.MaxLevel(), 1, true, false, ecd)

		require.NoError(t, err)

		galEls := mulParams.GaloisElements(params)
		galEls = MulParametersGaloisElements(params, rows, true, false)

		rlk := tc.kgen.GenRelinearizationKeyNew(tc.sk)
		gks := tc.kgen.GenGaloisKeysNew(galEls, tc.sk)

		eval := NewEvaluator(params, rows, tc.eval.WithKey(rlwe.NewMemEvaluationKeySet(rlk, gks...)))

		n := 4

		r := sampling.NewSource([32]byte{})

		in := make([]*mat.Dense, n)
		for i := range in {
			m := make([]float64, rows*rows)
			for j := range m {
				m[j] = r.Float64(-0.1, 0.1)
			}
			in[i] = mat.NewDense(rows, rows, m)
		}

		w := make([]*mat.Dense, n)
		for i := range w {
			m := make([]float64, rows*rows)
			for j := range m {
				m[j] = r.Float64(-0.1, 0.1)
			}
			w[i] = mat.NewDense(rows, rows, m)
		}

		ct0, err := enc.EncryptNew(in[:n], 0, matPerCt)
		require.NoError(t, err)

		ct1, err := enc.EncryptNew(w[:n], 0, matPerCt)
		require.NoError(t, err)

		now := time.Now()
		require.NoError(t, eval.MulCt(ct0, ct1, mulParams, ct0))
		eval.Rescale(ct0, ct0)
		fmt.Println(time.Since(now))

		have, err := dec.DecryptNew(ct0, rows, rows, 0, matPerCt)
		require.NoError(t, err)

		want := mat.NewDense(rows, rows, make([]float64, rows*rows))
		for i := range n {
			want.Mul(in[i].T(), w[i])
			hefloat.VerifyTestVectors(params, tc.ecd, nil, have[i].RawMatrix().Data, want.RawMatrix().Data, params.LogDefaultScale(), 0, *printPrecisionStats, t)
		}
	})

	t.Run("CtxPt", func(t *testing.T) {

		rows := 25
		cols := 39

		matPerCt := params.MaxSlots() / (rows * cols)

		ecd := NewEncoder(params)

		n := 2

		r := sampling.NewSource([32]byte{})

		in := make([]*mat.Dense, n)
		for i := range in {
			m := make([]float64, rows*cols)
			for j := range m {
				m[j] = r.Float64(-0.1, 0.1)
			}
			in[i] = mat.NewDense(rows, cols, m)
		}

		w := mat.NewDense(cols, cols, make([]float64, cols*cols))
		for j := range cols * cols {
			w.RawMatrix().Data[j] = r.Float64(-0.1, 0.1)
		}

		ct, err := enc.EncryptNew(in[:n], 0, matPerCt)
		require.NoError(t, err)

		pt, err := ecd.EncodeMulNew(w, params.MaxLevel())
		require.NoError(t, err)

		galEls := pt.GaloisElements(params)

		gks := tc.kgen.GenGaloisKeysNew(galEls, tc.sk)

		eval := NewEvaluator(params, rows, tc.eval.WithKey(rlwe.NewMemEvaluationKeySet(nil, gks...)))

		now := time.Now()
		require.NoError(t, eval.MulPt(ct, pt, ct))
		require.NoError(t, eval.Rescale(ct, ct))
		fmt.Println(time.Since(now))

		have, err := dec.DecryptNew(ct, rows, cols, 0, matPerCt)
		require.NoError(t, err)

		want := mat.NewDense(rows, cols, make([]float64, rows*cols))
		for i := range n {
			want.Mul(in[i], w)
			hefloat.VerifyTestVectors(params, tc.ecd, nil, have[i].RawMatrix().Data, want.RawMatrix().Data, params.LogDefaultScale(), 0, *printPrecisionStats, t)
		}
	})
}
