package normalization

import (
	"fmt"
	"math"
	"testing"

	"gonum.org/v1/gonum/mat"

	"app/bootstrapping"
	"app/matrix"

	"github.com/Pro7ech/lattigo/he/hefloat"
	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils/sampling"

	"github.com/stretchr/testify/require"
)

var paramsInsecure = hefloat.ParametersLiteral{
	LogN:            10,
	LogQ:            []int{60, 45, 45, 45, 45, 45, 45, 45, 45, 45, 45, 45},
	LogP:            []int{60, 60, 60},
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

func TestNormalization(t *testing.T) {

	params, err := hefloat.NewParametersFromLiteral(paramsInsecure)
	require.NoError(t, err)

	tc := newTestContext(params)

	rows := 25
	cols := 32

	in := mat.NewDense(rows, cols, make([]float64, rows*cols))

	r := sampling.NewSource([32]byte{})

	for i := range rows * cols {
		in.RawMatrix().Data[i] = r.Float64(-14, 14)
	}

	gamma := make([]float64, cols)
	beta := make([]float64, cols)

	for i := range cols {
		gamma[i] = r.Float64(-2, 2)
		beta[i] = r.Float64(-2, 2)
	}

	A := 1.0
	B := 90.0
	deg := 63
	iters := 0

	p := Parameters{
		Gamma:           gamma,
		Beta:            beta,
		InvSqrtMin:      A,
		InvSqrtMax:      B,
		InvSqrtDeg:      deg,
		InvSqrtIter:     iters,
		ToTVecSize:      rows * cols,
		BootstrapBefore: true,
	}

	eval := NewEvaluator(p, nil, nil)

	fmt.Println("Depth:", eval.CircuitDepth())

	want := mat.NewDense(rows, cols, make([]float64, rows*cols))

	eval.EvaluateExact(in, want)

	t.Run("Approximate", func(t *testing.T) {
		have := mat.NewDense(rows, cols, make([]float64, rows*cols))
		eval.EvaluateApproximate(in, have)
		hefloat.VerifyTestVectors(params, tc.ecd, nil, want.RawMatrix().Data, have.RawMatrix().Data, 30, 0, true, t)
	})

	t.Run("Encrypted", func(t *testing.T) {

		kgen := tc.kgen
		sk := tc.sk
		enc := tc.enc
		ecd := tc.ecd
		dec := tc.dec

		galEls := GaloisElements(params, cols)

		rlk := kgen.GenRelinearizationKeyNew(sk)
		evk := rlwe.NewMemEvaluationKeySet(rlk, kgen.GenGaloisKeysNew(galEls, sk)...)

		eval.Evaluator = matrix.NewEvaluator(params, cols, []*hefloat.Evaluator{tc.eval.WithKey(evk)})
		eval.Bootstrapper = bootstrapping.NewDummyBootstrapper(params, 1, sk)

		pt := hefloat.NewPlaintext(params, params.MaxLevel())

		require.NoError(t, ecd.Encode(in.RawMatrix().Data, pt))
		ct := hefloat.NewCiphertext(params, 1, params.MaxLevel())
		require.NoError(t, enc.Encrypt(pt, ct))

		cts := []rlwe.Ciphertext{*ct}

		require.NoError(t, eval.EvaluateEncrypted(cts, cols))

		have := make([]float64, rows*cols)
		require.NoError(t, ecd.Decode(dec.DecryptNew(&cts[0]), have))

		wantData := want.RawMatrix().Data

		for i := range 2 * cols {
			if i%cols == 0 && i > 0 {
				fmt.Println()
			}
			fmt.Printf("%2d - %15.7f %15.7f %20.17f \n", i, wantData[i], have[i], math.Abs(wantData[i]-have[i]))
		}

		hefloat.VerifyTestVectors(params, ecd, nil, wantData, have, 30, 0, true, t)

	})
}
