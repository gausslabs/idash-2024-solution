package matrix
/*
import (
	"fmt"
	"testing"
	"time"

	"gonum.org/v1/gonum/mat"

	"golang.org/x/exp/maps"

	"github.com/Pro7ech/lattigo/he/hefloat"
	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils/sampling"

	"github.com/stretchr/testify/require"
)
*/

/*
func TestSplitAndMerge(t *testing.T) {

	params, err := hefloat.NewParametersFromLiteral(hefloat.ParametersLiteral{
		LogN:            13,
		LogQ:            []int{60, 45, 45},
		LogP:            []int{60},
		LogDefaultScale: 45,
		RingType:        ring.ConjugateInvariant,
	})
	require.NoError(t, err)
	tc := newTestContext(params)

	kgen := tc.kgen
	sk := tc.sk

	enc := NewEncryptor(params, sk)
	dec := NewDecryptor(params, sk)

	rows := 25
	cols := 64
	split := 4
	padd := rows - cols/split

	eval := NewEvaluator(params, rows, tc.eval.WithKey(rlwe.NewMemEvaluationKeySet(nil, gks...)))

	ltSplit, err := eval.NewLinearTransformation(
		params,
		params.MaxLevel(),
		params.DefaultScale(),
		params.DefaultScale(),
		false,
		SplitDiagonals(params, rows, cols, split, padd, 1),
		tc.ecd)

	require.NoError(t, err)

	ltMerge, err := eval.NewLinearTransformation(
		params,
		params.MaxLevel()-1,
		params.DefaultScale(),
		params.DefaultScale(),
		false,
		MergeDiagonals(params, rows, cols, split, padd, 1),
		tc.ecd)

	galEls := append(ltSplit.GaloisElements(params), ltMerge.GaloisElements(params)...)

	m := map[uint64]bool{}
	for _, galEl := range galEls {
		m[galEl] = true
	}

	fmt.Println("galoisElements", len(m))

	gks := kgen.GenGaloisKeysNew(maps.Keys(m), sk)

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

	ct, err := enc.EncryptNew(in, 0, n)
	require.NoError(t, err)

	
	now := time.Now()
	require.NoError(t, eval.EvaluateLinearTransformation(ct, ltSplit, ct))
	require.NoError(t, eval.Rescale(ct, ct))
	fmt.Println(time.Since(now))

	have, err := dec.DecryptNew(ct, rows, cols/split, padd, n*split)
	require.NoError(t, err)

	want := []*mat.Dense{}
	for i := range in {
		want = append(want, SplitHeads(in[i], split)...)
	}

	for i := range have {
		hefloat.VerifyTestVectors(params, tc.ecd, nil, have[i].RawMatrix().Data, want[i].RawMatrix().Data, params.LogDefaultScale(), 0, *printPrecisionStats, t)
	}

	now = time.Now()
	require.NoError(t, eval.EvaluateLinearTransformation(ct, ltMerge, ct))
	require.NoError(t, eval.Rescale(ct, ct))
	fmt.Println(time.Since(now))

	have, err = dec.DecryptNew(ct, rows, cols, 0, n)
	require.NoError(t, err)

	for i := range in {
		hefloat.VerifyTestVectors(params, tc.ecd, nil, have[i].RawMatrix().Data, in[i].RawMatrix().Data, params.LogDefaultScale(), 0, *printPrecisionStats, t)
	}
}
*/