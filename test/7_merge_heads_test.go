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

func TestMergeHeads(t *testing.T) {

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

	galEls := s.MergeHeadsGaloisElements(params)

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

	QMulKTMulVPlain := s.UpToQMulKTMulV(data)

	var QMulKTMulVEnc []rlwe.Ciphertext
	QMulKTMulVEnc, err = c.EncryptNew(utils.Flatten(QMulKTMulVPlain), lib.Padding, lib.NbMatPerCtIn*lib.Split)
	require.NoError(t, err)

	require.NoError(t, s.MergeHeadsEncrypted(QMulKTMulVEnc))

	MergeHeadsPlain := s.MergeHeadsApproximate(QMulKTMulVPlain)

	MergeHeadsHave, err := c.DecryptNew(QMulKTMulVEnc, lib.Rows, lib.Cols, 0, lib.NbMatPerCtIn)
	require.NoError(t, err)
	for i := range MergeHeadsPlain {
		stats := hefloat.GetPrecisionStats(params, ecd, nil, MergeHeadsPlain[i].RawMatrix().Data, MergeHeadsHave[i].RawMatrix().Data, 0, true)
		fmt.Println(stats)
	}
}
