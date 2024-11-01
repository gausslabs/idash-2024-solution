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

func TestQKV(t *testing.T) {

	params := lib.NewParametersCustom(lib.LogN, lib.LevelBootstrapping)

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

	galEls := s.QKVGaloisElements(params)

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

	in := s.UpToPositionalEncoding(data)

	var cts []rlwe.Ciphertext
	cts, err = c.EncryptNew(in, 0, lib.NbMatPerCtIn)
	require.NoError(t, err)

	QEnc, KEnc, VEnc, err := s.QKVEncrypted(cts)
	require.NoError(t, err)

	QPlain, KPlain, VPlain := s.QKVApproximate(in)

	QHave, err := c.DecryptNew(QEnc, lib.Rows, lib.Cols, 0, lib.NbMatPerCtIn)
	require.NoError(t, err)
	for i := range QPlain {
		stats := hefloat.GetPrecisionStats(params, ecd, nil, QPlain[i].RawMatrix().Data, QHave[i].RawMatrix().Data, 0, true)
		fmt.Println(stats)
	}

	KHave, err := c.DecryptNew(KEnc, lib.Rows, lib.Cols, 0, lib.NbMatPerCtIn)
	require.NoError(t, err)
	for i := range KPlain {
		stats := hefloat.GetPrecisionStats(params, ecd, nil, KPlain[i].RawMatrix().Data, KHave[i].RawMatrix().Data, 0, true)
		fmt.Println(stats)
	}

	VHave, err := c.DecryptNew(VEnc, lib.Rows, lib.Cols, 0, lib.NbMatPerCtIn)
	require.NoError(t, err)
	for i := range VPlain {
		stats := hefloat.GetPrecisionStats(params, ecd, nil, VPlain[i].RawMatrix().Data, VHave[i].RawMatrix().Data, 0, true)
		fmt.Println(stats)
	}
}
