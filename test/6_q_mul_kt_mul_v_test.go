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

func TestQMulKTMulV(t *testing.T) {

	params := lib.NewParametersCustom(lib.LogN, 3)

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

	galEls := s.QMulKTMulVGaloisElements(params)

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

	QMulKTPlain, VPlain := s.UpToSoftMax(data)

	var QMulKTEnc, VEnc []rlwe.Ciphertext

	QMulKTEnc, err = c.EncryptNew(utils.Flatten(QMulKTPlain), 0, lib.NbMatPerCtIn*lib.Split)
	require.NoError(t, err)

	VEnc, err = c.EncryptNew(utils.Flatten(VPlain), lib.Padding, lib.NbMatPerCtIn*lib.Split)
	require.NoError(t, err)

	QKTMulVEnc := QMulKTEnc
	require.NoError(t, s.QKTMulVEncrypted(QMulKTEnc, VEnc, QKTMulVEnc, nil))

	QKTMulVPlain := s.QKTMulVApproximate(QMulKTPlain, VPlain)

	QKTMulVHave, err := c.DecryptNew(QKTMulVEnc, lib.Rows, lib.Cols/lib.Split, lib.Padding, lib.NbMatPerCtIn*lib.Split)
	require.NoError(t, err)
	for i := range QKTMulVPlain {
		for j := range QKTMulVPlain[i] {
			stats := hefloat.GetPrecisionStats(params, ecd, nil, QKTMulVPlain[i][j].RawMatrix().Data, QKTMulVHave[i*lib.Split+j].RawMatrix().Data, 0, true)
			fmt.Println(stats)
		}
	}
}
