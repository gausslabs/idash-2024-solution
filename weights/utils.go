package weights

import (
	"app/lib"
	"app/utils"

	"gonum.org/v1/gonum/mat"
)

func GetBias(rows int, b []float64) (m *mat.Dense) {
	cols := len(b)
	m = mat.NewDense(rows, cols, make([]float64, rows*cols))
	for i := range rows {
		copy(m.RawMatrix().Data[i*cols:(i+1)*cols], b)
	}
	return
}

func LoadEmbeddingLUT(path string) (w *mat.Dense) {
	data, err := utils.ReadFile(path+"/embedding.csv", ',', 0, false, lib.NumCPU)
	if err != nil {
		panic(err)
	}

	return mat.NewDense(25, lib.Cols, data[0][:25*lib.Cols])
}

func LoadTransformerBlockValueWeights(path string) (w *mat.Dense, b []float64) {

	weights, err := utils.ReadFile(path+"/transformer_block_value_weights.csv", ',', 0, false, lib.NumCPU)
	if err != nil {
		panic(err)
	}

	return mat.NewDense(lib.Cols, lib.Cols, weights[0][:lib.Cols*lib.Cols]), weights[0][128*128 : 128*128+lib.Cols]
}

func LoadTransformerBlockKeyWeights(path string) (w *mat.Dense, b []float64) {

	weights, err := utils.ReadFile(path+"/transformer_block_key_weights.csv", ',', 0, false, lib.NumCPU)
	if err != nil {
		panic(err)
	}

	return mat.NewDense(lib.Cols, lib.Cols, weights[0][:lib.Cols*lib.Cols]), weights[0][128*128 : 128*128+lib.Cols]
}

func LoadTransformerBlockQueryWeights(path string) (w *mat.Dense, b []float64) {

	weights, err := utils.ReadFile(path+"/transformer_block_query_weights.csv", ',', 0, false, lib.NumCPU)
	if err != nil {
		panic(err)
	}

	return mat.NewDense(lib.Cols, lib.Cols, weights[0][:lib.Cols*lib.Cols]), weights[0][128*128 : 128*128+lib.Cols]
}

func LoadTransformerBlockCombineWeights(path string) (w *mat.Dense, b []float64) {

	weights, err := utils.ReadFile(path+"/transformer_block_combine_weights.csv", ',', 0, false, lib.NumCPU)
	if err != nil {
		panic(err)
	}

	return mat.NewDense(lib.Cols, lib.Cols, weights[0][:lib.Cols*lib.Cols]), weights[0][128*128 : 128*128+lib.Cols]
}

func LoadTransformerBlockNorm1Weights(path string) (gamma, beta []float64) {

	weights, err := utils.ReadFile(path+"/transformer_block_norm1_weights.csv", ',', 0, false, lib.NumCPU)
	if err != nil {
		panic(err)
	}

	return weights[0][:lib.Cols], weights[0][128 : 128+lib.Cols]
}

func LoadTransformerBlockNorm2Weights(path string) (gamma, beta []float64) {

	weights, err := utils.ReadFile(path+"/transformer_block_norm2_weights.csv", ',', 0, false, lib.NumCPU)
	if err != nil {
		panic(err)
	}

	return weights[0][:lib.Cols], weights[0][128 : 128+lib.Cols]
}

func LoadTransformerBlockFNNWeights(path string) (w0 *mat.Dense, b0 []float64, w1 *mat.Dense, b1 []float64) {

	weights, err := utils.ReadFile(path+"/transformer_block_fnn_weights.csv", ',', 0, false, lib.NumCPU)
	if err != nil {
		panic(err)
	}

	var ptr int
	w0 = mat.NewDense(lib.Cols, 2*lib.Cols, weights[0][ptr:ptr+lib.Cols*2*lib.Cols])
	ptr += 128 * 256
	b0 = weights[0][ptr : ptr+2*lib.Cols]
	ptr += 256
	w1 = mat.NewDense(2*lib.Cols, lib.Cols, weights[0][ptr:ptr+2*lib.Cols*lib.Cols])
	ptr += 256 * 128
	b1 = weights[0][ptr : ptr+lib.Cols]
	ptr += 128
	return
}

func LoadClassifierWeights(path string) (w *mat.Dense, b []float64) {
	weights, err := utils.ReadFile(path+"/classifier_weights.csv", ',', 0, false, lib.NumCPU)
	if err != nil {
		panic(err)
	}

	return mat.NewDense(lib.Cols, lib.Classes, weights[0][:lib.Cols*lib.Classes]), weights[0][lib.Cols*lib.Classes : (lib.Cols+1)*lib.Classes]
}
