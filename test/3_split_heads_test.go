package qkv

import (
	"fmt"
	"testing"
	"time"

	"app/client"
	"app/lib"
	"app/server"

	"github.com/Pro7ech/lattigo/he/hefloat"
	"github.com/Pro7ech/lattigo/rlwe"

	"github.com/stretchr/testify/require"
)

func TestSplitHeads(t *testing.T) {

	params := lib.NewParametersCustom(lib.LogN, 1)

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

	galEls := s.SplitHeadsGaloisElements(params)

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

	QPlain, KPlain, VPlain := s.UpToQKV(data)

	var QEnc, KEnc, VEnc []rlwe.Ciphertext

	QEnc, err = c.EncryptNew(QPlain, 0, lib.NbMatPerCtIn)
	require.NoError(t, err)

	KEnc, err = c.EncryptNew(KPlain, 0, lib.NbMatPerCtIn)
	require.NoError(t, err)

	VEnc, err = c.EncryptNew(VPlain, 0, lib.NbMatPerCtIn)
	require.NoError(t, err)

	require.NoError(t, s.SplitHeadsEncrypted(QEnc, KEnc, VEnc))

	QSplitPlain, KSplitPlain, VSplitPlain := s.SplitHeadsApproximate(QPlain, KPlain, VPlain)

	QSplitEnc, err := c.DecryptNew(QEnc, lib.Rows, lib.Cols/lib.Split, lib.Padding, lib.NbMatPerCtIn*lib.Split)
	require.NoError(t, err)
	for i := range QSplitPlain {
		for j := range QSplitPlain[i] {
			stats := hefloat.GetPrecisionStats(params, ecd, nil, QSplitPlain[i][j].RawMatrix().Data, QSplitEnc[i*lib.Split+j].RawMatrix().Data, 0, true)
			fmt.Println(stats)
		}
	}

	KSplitEnc, err := c.DecryptNew(KEnc, lib.Rows, lib.Cols/lib.Split, lib.Padding, lib.NbMatPerCtIn*lib.Split)
	require.NoError(t, err)
	for i := range KSplitPlain {
		for j := range KSplitPlain[i] {
			stats := hefloat.GetPrecisionStats(params, ecd, nil, KSplitPlain[i][j].RawMatrix().Data, KSplitEnc[i*lib.Split+j].RawMatrix().Data, 0, true)
			fmt.Println(stats)
		}
	}

	VSplitEnc, err := c.DecryptNew(VEnc, lib.Rows, lib.Cols/lib.Split, lib.Padding, lib.NbMatPerCtIn*lib.Split)
	require.NoError(t, err)

	for i := range VSplitPlain {
		for j := range VSplitPlain[i] {
			stats := hefloat.GetPrecisionStats(params, ecd, nil, VSplitPlain[i][j].RawMatrix().Data, VSplitEnc[i*lib.Split+j].RawMatrix().Data, 0, true)
			fmt.Println(stats)
		}
	}
}
