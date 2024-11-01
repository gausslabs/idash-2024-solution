package qkv

import (
	"fmt"
	"testing"
	"time"

	"app/client"
	"app/lib"
	"app/server"
	"app/utils"

	"github.com/Pro7ech/lattigo/he/hefloat"
	"github.com/Pro7ech/lattigo/rlwe"

	"github.com/stretchr/testify/require"
)

func TestQMulKT(t *testing.T) {

	params := lib.NewParametersCustom(lib.LogN, 4)

	if tot := lib.NbMatPerCtIn * lib.Split * (lib.Rows * (lib.Cols/lib.Split + lib.Padding)); tot > params.MaxSlots() {
		panic(fmt.Errorf("invalid parameters: %d slots < split * #padded matrices = %d", params.MaxSlots(), tot))
	}

	ecd := hefloat.NewEncoder(params)

	kgen := rlwe.NewKeyGenerator(params)
	sk := kgen.GenSecretKeyNew()

	now := time.Now()
	fmt.Printf("Server: ")
	s := server.NewServer("../weights", lib.NumCPU)
	fmt.Printf("%s\n", time.Since(now))

	galEls := s.QMulKTGaloisElements(params)

	t.Logf("GaloisElements: %d\n", len(galEls))

	fmt.Printf("Client: ")
	now = time.Now()
	c := client.NewClient(params, sk)
	fmt.Printf("%s\n", time.Since(now))

	fmt.Printf("Kgen: ")
	now = time.Now()
	evk := c.GetKeyManager(len(galEls), sk)
	s.SetKeyManager(evk)
	fmt.Printf("%s\n", time.Since(now))

	data, _, err := c.Load("../data/example_AA_sequences.list", lib.SamplesStart, lib.SamplesEnd)
	require.NoError(t, err)

	QSplitPlain, KSplitPlain, _ := s.UpToSplitHeads(data)
	QMulKTSplitPlain := s.QMulKTApproximate(QSplitPlain, KSplitPlain)

	var QSplitEnc, KSplitEnc []rlwe.Ciphertext

	QSplitEnc, err = c.EncryptNew(utils.Flatten(QSplitPlain), lib.Padding, lib.NbMatPerCtIn*lib.Split)
	require.NoError(t, err)

	KSplitEnc, err = c.EncryptNew(utils.Flatten(KSplitPlain), lib.Padding, lib.NbMatPerCtIn*lib.Split)
	require.NoError(t, err)

	QMulKTEnc := QSplitEnc

	require.NoError(t, s.QMulKTEncrypted(QSplitEnc, KSplitEnc, QMulKTEnc))

	QMulKTHave, err := c.DecryptNew(QMulKTEnc, lib.Rows, lib.Rows, 0, lib.NbMatPerCtIn*lib.Split)
	require.NoError(t, err)
	for i := range QMulKTSplitPlain {
		for j := range QMulKTSplitPlain[i] {
			fmt.Println(QMulKTSplitPlain[i][j].RawMatrix().Data[:8])
			stats := hefloat.GetPrecisionStats(params, ecd, nil, QMulKTSplitPlain[i][j].RawMatrix().Data, QMulKTHave[i*lib.Split+j].RawMatrix().Data, 0, true)
			fmt.Println(stats)
		}
	}
}
