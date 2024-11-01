package innermax

import (
	"flag"
	"fmt"

	//"math"
	"slices"
	"testing"

	"app/bootstrapping"
	"app/matrix"

	"github.com/Pro7ech/lattigo/he/hefloat"
	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils/sampling"

	"github.com/stretchr/testify/require"
)

var printPrecisionStats = flag.Bool("print-precision", false, "print precision stats")

func TestInnermax(t *testing.T) {

	var err error

	A := -0.5
	B := 0.5
	K := 50
	D := 34

	absolutemax := 8

	params, err := hefloat.NewParametersFromLiteral(hefloat.ParametersLiteral{
		LogN:            10,
		LogQ:            []int{60, 45, 45, 45, 45, 45, 45, 45, 45, 45, 45, 45, 45},
		LogP:            []int{58, 58, 58},
		LogDefaultScale: 45,
		RingType:        ring.ConjugateInvariant,
		Xs:              &ring.Ternary{H: 192},
	})

	var n int

	if maxSlots := params.MaxSlots(); maxSlots%K == 0 {
		n = maxSlots
	} else {
		n = (maxSlots / K) * K
	}

	r := sampling.NewSource([32]byte{})

	values := make([][]float64, D)

	for i := range values {
		m := make([]float64, n)
		for j := range m {
			m[j] = r.Float64(A, B)
		}

		for j := range n / K {
			m[j*K] = 1 + (1/256.0)*float64(i*(n/K)+j)
		}

		values[i] = m
	}

	/*
		for i := range values{
			for j := range values[i]{
				fmt.Printf("%10.7f ", values[i][j])
			}
			fmt.Println()
		}
		fmt.Println()
	*/

	t.Run("Encrypted", func(t *testing.T) {

		kgen := rlwe.NewKeyGenerator(params)
		sk := kgen.GenSecretKeyNew()
		enc := rlwe.NewEncryptor(params, sk)
		dec := rlwe.NewDecryptor(params, sk)
		ecd := hefloat.NewEncoder(params)

		btp := bootstrapping.NewDummyBootstrapper(params, 1, sk)

		evals := make([]*hefloat.Evaluator, 1)
		evals[0] = hefloat.NewEvaluator(params, nil)

		mEval := matrix.NewEvaluator(params, K, evals)

		rlk := kgen.GenRelinearizationKeyNew(sk)
		galEls := GaloisElements(params, K, D)
		evk := rlwe.NewMemEvaluationKeySet(rlk, kgen.GenGaloisKeysNew(galEls, sk)...)

		pt := hefloat.NewPlaintext(params, params.MaxLevel())

		cts := make([]rlwe.Ciphertext, D)

		for i := range cts {
			require.NoError(t, ecd.Encode(values[i], pt))
			ct := hefloat.NewCiphertext(params, 1, params.MaxLevel())
			require.NoError(t, enc.Encrypt(pt, ct))
			cts[i] = *ct
		}

		eval := NewEvaluator(mEval, btp)
		eval.SetKeys(evk)

		cts, err = eval.InnerMax(cts, absolutemax, K)
		require.NoError(t, err)

		have := make([][]float64, D)
		want := make([][]float64, D)
		for i := range len(cts) {
			m := make([]float64, cts[i].Slots())
			require.NoError(t, ecd.Decode(dec.DecryptNew(&cts[i]), m))

			have[i] = make([]float64, n/K)
			for j := range n / K {
				have[i][j] = m[j*K]
			}

			want[i] = make([]float64, n/K)
			for j := range n / K {
				want[i][j] = slices.Max(values[i][j*K : (j+1)*K])
			}
			fmt.Println(i, want[i], have[i])
			hefloat.VerifyTestVectors(params, ecd, nil, want[i], have[i], 25.0, 0, *printPrecisionStats, t)
		}

		/*
			for j := range 4 * K {
					if j%K == 0 && j > 0 {
						fmt.Println()
					}
					fmt.Printf("%2d ", j)
					for k := range D{
						fmt.Printf("%11.5f", values[k][j])
					}
					fmt.Printf("     |")

					for k := range have{
						fmt.Printf("%11.5f", have[k][j])
					}
					fmt.Println()
				}
				fmt.Println()
		*/

		//

	})

}
