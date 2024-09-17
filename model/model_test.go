package model

import (
	"fmt"
	"testing"

	"gonum.org/v1/gonum/mat"

	"app/client"
	"app/lib"
	"app/server"
	"app/utils"

	"github.com/stretchr/testify/require"
)

func TestModel(t *testing.T) {

	start := 0
	end := 1000

	c := client.Client{}
	in, _, err := c.Load("../data/example_AA_sequences.list", start, end)
	//in, err := c.LoadSynthetic("../data/example_AA_sequences.list", end-start)
	//in, err := c.LoadFuzzy(end - start)
	require.NoError(t, err)

	model := server.NewServer("../weights", 1)
	model.Debug = true

	have := model.RunApproximate(in)
	model.SoftmaxExact(have)

	want, err := utils.ReadFile("test_vector/5_classifier.csv", ',', 0, false, lib.NumCPU)
	require.NoError(t, err)

	wantM := make([]*mat.Dense, len(have))
	for i := range wantM {
		wantM[i] = mat.NewDense(1, lib.Classes, want[i])
	}

	fmt.Println(utils.Precision(have, wantM))
}
