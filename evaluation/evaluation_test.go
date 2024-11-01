package evaluation

import (
	"flag"
	"fmt"
	"testing"
	"time"

	"gonum.org/v1/gonum/mat"

	"app/client"
	"app/lib"
	"app/server"
	"app/utils"

	"github.com/Pro7ech/lattigo/he/hefloat"
	"github.com/Pro7ech/lattigo/rlwe"

	"github.com/stretchr/testify/require"
)

var printPrecisionStats = flag.Bool("print-precision", false, "print precision stats")
var minprec int = 10 + lib.LogN + 2

func TestServer(t *testing.T) {

	nbMatPerCt := lib.NbMatPerCtIn

	params := lib.NewParameters()

	if tot := nbMatPerCt * lib.Split * (lib.Rows * (lib.Cols/lib.Split + lib.Padding)); tot > params.MaxSlots() {
		t.Fatalf("invalid parameters: %d slots < split * #padded matrices = %d", params.MaxSlots(), tot)
	}

	ecd := hefloat.NewEncoder(params)

	kgen := rlwe.NewKeyGenerator(params)
	sk := kgen.GenSecretKeyNew()

	fmt.Println(params.LogN(), params.LogQP())

	btp := lib.NewDummyBootstrapper(params, sk)
	//btp := lib.NewBootstrapper(params, sk)
	btp.Debug = true

	now := time.Now()
	fmt.Printf("Server: ")
	s := server.NewServer("../weights", lib.NumCPU)
	fmt.Printf("%s\n", time.Since(now))

	galEls, maxconcurrentkeys := s.GaloisElements(params)

	t.Logf("GaloisElements: %d\n", len(galEls))
	t.Logf("MaxConcurrentKeys: %d\n", maxconcurrentkeys)

	fmt.Printf("Client: ")
	now = time.Now()
	c := client.NewClient(params, sk)
	fmt.Printf("%s\n", time.Since(now))

	fmt.Printf("Kgen: ")
	now = time.Now()
	s.SetKeyManager(c.GetKeyManager(maxconcurrentkeys, sk))
	fmt.Printf("%s\n", time.Since(now))

	now = time.Now()
	fmt.Printf("Client.LoadData: ")
	X, _, err := c.Load("../data/example_AA_sequences.list", lib.SamplesStart, lib.SamplesEnd)
	if err != nil {
		panic(err)
	}
	require.NoError(t, err)
	fmt.Printf("%s\n", time.Since(now))

	now = time.Now()
	fmt.Printf("Client.Encrypt: ")
	ct, err := c.EncryptNew(X, 0, nbMatPerCt)
	require.NoError(t, err)
	fmt.Printf("%s\n", time.Since(now))

	inWant := s.EmbedApproximate(X)

	t.Run("Embedding", func(t *testing.T) {
		now = time.Now()
		ct, err = s.EmbedEncrypted(ct)
		require.NoError(t, err)
		have, err := c.DecryptNew(ct, lib.Rows, lib.Cols, 0, nbMatPerCt)
		require.NoError(t, err)
		for i := range inWant {
			hefloat.VerifyTestVectors(params, ecd, nil, inWant[i].RawMatrix().Data, have[i].RawMatrix().Data, minprec, 0, *printPrecisionStats, t)
		}
	})

	s.PositionalEncodingApproximate(inWant, inWant)

	t.Run("PositionalEncoding", func(t *testing.T) {
		require.NoError(t, s.PositionalEncodingEncrypted(ct, ct))
		have, err := c.DecryptNew(ct, lib.Rows, lib.Cols, 0, nbMatPerCt)
		require.NoError(t, err)
		for i := range inWant {
			hefloat.VerifyTestVectors(params, ecd, nil, inWant[i].RawMatrix().Data, have[i].RawMatrix().Data, minprec, 0, *printPrecisionStats, t)
		}
	})

	var Q, K, V []rlwe.Ciphertext
	QWant, KWant, VWant := s.QKVApproximate(inWant)
	t.Run("QKV", func(t *testing.T) {
		Q, K, V, err = s.QKVEncrypted(ct)
		require.NoError(t, err)
		QHave, err := c.DecryptNew(Q, lib.Rows, lib.Cols, 0, nbMatPerCt)
		require.NoError(t, err)
		for i := range QWant {
			hefloat.VerifyTestVectors(params, ecd, nil, QWant[i].RawMatrix().Data, QHave[i].RawMatrix().Data, minprec, 0, *printPrecisionStats, t)
		}
		KHave, err := c.DecryptNew(K, lib.Rows, lib.Cols, 0, nbMatPerCt)
		require.NoError(t, err)
		for i := range KWant {
			hefloat.VerifyTestVectors(params, ecd, nil, KWant[i].RawMatrix().Data, KHave[i].RawMatrix().Data, minprec, 0, *printPrecisionStats, t)
		}
		VHave, err := c.DecryptNew(V, lib.Rows, lib.Cols, 0, nbMatPerCt)
		require.NoError(t, err)
		for i := range VWant {
			hefloat.VerifyTestVectors(params, ecd, nil, VWant[i].RawMatrix().Data, VHave[i].RawMatrix().Data, minprec, 0, *printPrecisionStats, t)
		}
	})

	QSplitWant, KSplitWant, VSplitWant := s.SplitHeadsApproximate(QWant, KWant, VWant)
	t.Run("SplitHeads", func(t *testing.T) {
		require.NoError(t, s.SplitHeadsEncrypted(Q, K, V))
		QSplitHave, err := c.DecryptNew(Q, lib.Rows, lib.Cols/lib.Split, lib.Padding, nbMatPerCt*lib.Split)
		require.NoError(t, err)
		for i := range QSplitWant {
			for j := range QSplitWant[i] {
				hefloat.VerifyTestVectors(params, ecd, nil, QSplitWant[i][j].RawMatrix().Data, QSplitHave[i*lib.Split+j].RawMatrix().Data, minprec, 0, *printPrecisionStats, t)
			}
		}
		KHave, err := c.DecryptNew(K, lib.Rows, lib.Cols/lib.Split, lib.Padding, nbMatPerCt*lib.Split)
		require.NoError(t, err)
		for i := range KSplitWant {
			for j := range KSplitWant[i] {
				hefloat.VerifyTestVectors(params, ecd, nil, KSplitWant[i][j].RawMatrix().Data, KHave[i*lib.Split+j].RawMatrix().Data, minprec, 0, *printPrecisionStats, t)
			}
		}
		VHave, err := c.DecryptNew(V, lib.Rows, lib.Cols/lib.Split, lib.Padding, nbMatPerCt*lib.Split)
		require.NoError(t, err)
		for i := range VSplitWant {
			for j := range VSplitWant[i] {
				hefloat.VerifyTestVectors(params, ecd, nil, VSplitWant[i][j].RawMatrix().Data, VHave[i*lib.Split+j].RawMatrix().Data, minprec, 0, *printPrecisionStats, t)
			}
		}
	})

	QMulKTSplitWant := s.QMulKTApproximate(QSplitWant, KSplitWant)
	var QMulKT []rlwe.Ciphertext
	t.Run("QMulKT", func(t *testing.T) {
		QMulKT = Q
		require.NoError(t, s.QMulKTEncrypted(Q, K, QMulKT))
		QMulKTHave, err := c.DecryptNew(QMulKT, lib.Rows, lib.Rows, 0, nbMatPerCt*lib.Split)
		require.NoError(t, err)
		for i := range QMulKTSplitWant {
			for j := range QMulKTSplitWant[i] {
				hefloat.VerifyTestVectors(params, ecd, nil, QMulKTSplitWant[i][j].RawMatrix().Data, QMulKTHave[i*lib.Split+j].RawMatrix().Data, minprec, 0, *printPrecisionStats, t)
			}
		}
	})

	t.Run("Bootstrap_0", func(t *testing.T) {
		QMulKT, err = btp.BootstrapMany(QMulKT)
		require.NoError(t, err)
		QMulKTHave, err := c.DecryptNew(QMulKT, lib.Rows, lib.Rows, 0, nbMatPerCt*lib.Split)
		require.NoError(t, err)
		for i := range QMulKTSplitWant {
			for j := range QMulKTSplitWant[i] {
				hefloat.VerifyTestVectors(params, ecd, nil, QMulKTSplitWant[i][j].RawMatrix().Data, QMulKTHave[i*lib.Split+j].RawMatrix().Data, minprec, 0, *printPrecisionStats, t)
			}
		}
	})

	s.SoftMaxApproximate(QMulKTSplitWant)
	t.Run("SoftMaxQMulKT", func(t *testing.T) {
		require.NoError(t, s.SoftMaxEncrypted(QMulKT, btp))
		QMulKTHave, err := c.DecryptNew(QMulKT, lib.Rows, lib.Rows, 0, nbMatPerCt*lib.Split)
		require.NoError(t, err)
		for i := range QMulKTSplitWant {
			for j := range QMulKTSplitWant[i] {
				hefloat.VerifyTestVectors(params, ecd, nil, QMulKTSplitWant[i][j].RawMatrix().Data, QMulKTHave[i*lib.Split+j].RawMatrix().Data, minprec, 0, *printPrecisionStats, t)
			}
		}
	})

	QKTMulVSplitWant := s.QKTMulVApproximate(QMulKTSplitWant, VSplitWant)
	var QKTMulV []rlwe.Ciphertext
	t.Run("QKTMulV", func(t *testing.T) {
		QKTMulV = QMulKT
		require.NoError(t, s.QKTMulVEncrypted(QMulKT, V, QKTMulV, btp))
		QKTMulVHave, err := c.DecryptNew(QKTMulV, lib.Rows, lib.Cols/lib.Split, lib.Padding, nbMatPerCt*lib.Split)
		require.NoError(t, err)
		for i := range QKTMulVSplitWant {
			for j := range QKTMulVSplitWant[i] {
				hefloat.VerifyTestVectors(params, ecd, nil, QKTMulVSplitWant[i][j].RawMatrix().Data, QKTMulVHave[i*lib.Split+j].RawMatrix().Data, minprec, 0, *printPrecisionStats, t)
			}
		}
	})

	QKTMulVWant := s.MergeHeadsApproximate(QKTMulVSplitWant)
	t.Run("MergeHeads", func(t *testing.T) {
		require.NoError(t, s.MergeHeadsEncrypted(QKTMulV))
		QKTMulVHave, err := c.DecryptNew(QKTMulV, lib.Rows, lib.Cols, 0, nbMatPerCt)
		require.NoError(t, err)
		for i := range QKTMulVWant {
			hefloat.VerifyTestVectors(params, ecd, nil, QKTMulVWant[i].RawMatrix().Data, QKTMulVHave[i].RawMatrix().Data, minprec, 0, *printPrecisionStats, t)
		}
	})

	s.CombineApproximate(inWant, QKTMulVWant)
	t.Run("Combine", func(t *testing.T) {
		require.NoError(t, s.CombineEncrypted(ct, QKTMulV))
		ctHave, err := c.DecryptNew(ct, lib.Rows, lib.Cols, 0, nbMatPerCt)
		require.NoError(t, err)
		for i := range inWant {
			hefloat.VerifyTestVectors(params, ecd, nil, inWant[i].RawMatrix().Data, ctHave[i].RawMatrix().Data, minprec, 0, *printPrecisionStats, t)
		}
	})

	t.Run("Bootstrap_1", func(t *testing.T) {
		ct, err = btp.BootstrapMany(ct)
		require.NoError(t, err)
		ctHave, err := c.DecryptNew(ct, lib.Rows, lib.Cols, 0, nbMatPerCt)
		require.NoError(t, err)
		for i := range inWant {
			hefloat.VerifyTestVectors(params, ecd, nil, inWant[i].RawMatrix().Data, ctHave[i].RawMatrix().Data, minprec, 0, *printPrecisionStats, t)
		}
	})

	s.Norm1Approximate(inWant)
	t.Run("Norm1", func(t *testing.T) {
		require.NoError(t, s.Norm1Encrypted(ct, btp))
		ctHave, err := c.DecryptNew(ct, lib.Rows, lib.Cols, 0, nbMatPerCt)
		require.NoError(t, err)
		for i := range inWant {
			hefloat.VerifyTestVectors(params, ecd, nil, inWant[i].RawMatrix().Data, ctHave[i].RawMatrix().Data, minprec, 0, *printPrecisionStats, t)
		}
	})

	s.FNNApproximate(inWant)
	t.Run("FNN", func(t *testing.T) {
		require.NoError(t, s.FNNEncrypted(ct, btp))
		ctHave, err := c.DecryptNew(ct, lib.Rows, lib.Cols, 0, nbMatPerCt)
		require.NoError(t, err)
		for i := range inWant {
			hefloat.VerifyTestVectors(params, ecd, nil, inWant[i].RawMatrix().Data, ctHave[i].RawMatrix().Data, minprec, 0, *printPrecisionStats, t)
		}
	})

	if ct[0].Level() < 3 {
		t.Run("Bootstrap", func(t *testing.T) {
			ct, err = btp.BootstrapMany(ct)
			require.NoError(t, err)
			ctHave, err := c.DecryptNew(ct, lib.Rows, lib.Cols, 0, nbMatPerCt)
			require.NoError(t, err)
			for i := range inWant {
				hefloat.VerifyTestVectors(params, ecd, nil, inWant[i].RawMatrix().Data, ctHave[i].RawMatrix().Data, minprec, 0, *printPrecisionStats, t)
			}
		})
	}

	s.Norm2Approximate(inWant)
	t.Run("Norm2", func(t *testing.T) {
		require.NoError(t, s.Norm2Encrypted(ct, btp))
		ctHave, err := c.DecryptNew(ct, lib.Rows, lib.Cols, 0, nbMatPerCt)
		require.NoError(t, err)
		for i := range inWant {
			hefloat.VerifyTestVectors(params, ecd, nil, inWant[i].RawMatrix().Data, ctHave[i].RawMatrix().Data, minprec, 0, *printPrecisionStats, t)
		}
	})

	if ct[0].Level() < 1 {
		t.Run("Bootstrap", func(t *testing.T) {
			ct, err = btp.BootstrapMany(ct)
			require.NoError(t, err)
			ctHave, err := c.DecryptNew(ct, lib.Rows, lib.Cols, 0, nbMatPerCt)
			require.NoError(t, err)
			for i := range inWant {
				hefloat.VerifyTestVectors(params, ecd, nil, inWant[i].RawMatrix().Data, ctHave[i].RawMatrix().Data, minprec, 0, *printPrecisionStats, t)
			}
		})
	}

	inWant = s.PoolingApproximate(inWant)
	t.Run("Pooling", func(t *testing.T) {
		ct, err = s.PoolingEncrypted(ct)
		require.NoError(t, err)
		ctHave, err := c.DecryptNew(ct, 1, lib.Cols, 0, lib.Rows*nbMatPerCt)
		require.NoError(t, err)
		ctHave = client.GetResults(ctHave)
		for i := range inWant {
			hefloat.VerifyTestVectors(params, ecd, nil, inWant[i].RawMatrix().Data, ctHave[i].RawMatrix().Data, minprec, 0, *printPrecisionStats, t)
		}
	})

	if ct[0].Level() < 1 {
		t.Run("Bootstrap", func(t *testing.T) {
			ct, err = btp.BootstrapMany(ct)
			require.NoError(t, err)
			ctHave, err := c.DecryptNew(ct, 1, lib.Cols, 0, lib.Rows*nbMatPerCt)
			require.NoError(t, err)
			ctHave = client.GetResults(ctHave)
			for i := range inWant {
				hefloat.VerifyTestVectors(params, ecd, nil, inWant[i].RawMatrix().Data, ctHave[i].RawMatrix().Data, minprec, 0, *printPrecisionStats, t)
			}
		})
	}

	inWant = s.ClassifierApproximate(inWant)
	t.Run("Classifier", func(t *testing.T) {
		require.NoError(t, s.ClassifierEncrypted(ct))
		ctHave, err := c.DecryptNew(ct, 1, lib.Classes, lib.Cols-lib.Classes, lib.Rows*nbMatPerCt)
		require.NoError(t, err)
		ctHave = client.GetResults(ctHave)
		for i := range inWant {
			hefloat.VerifyTestVectors(params, ecd, nil, inWant[i].RawMatrix().Data, ctHave[i].RawMatrix().Data, minprec, 0, *printPrecisionStats, t)
		}

		accuracy, noise := utils.Precision(ctHave, inWant)

		fmt.Printf("PT vs. CT Accuracy: %f\n", accuracy)
		fmt.Printf("CT AVG Noise: %f\n", noise)
	})
}

func Accuracy(have []int, want [][]float64) (acc0, acc1 float64) {
	for i := range want {
		if have[i] == int(want[i][0]) {
			acc0 += 1
		}
		if have[i] == int(want[i][1]) {
			acc1 += 1
		}
	}

	acc0 /= float64(len(want))
	acc1 /= float64(len(want))
	return
}

func GetLabelFromPrediction(in []*mat.Dense) (out []int) {
	out = make([]int, len(in))
	for i := range in {
		m := in[i].RawMatrix().Data
		var Max float64
		for j := range m {
			if m[j] > Max {
				Max = m[j]
				out[i] = j
			}
		}
	}
	return
}
