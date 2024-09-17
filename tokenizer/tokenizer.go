package tokenizer

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"gonum.org/v1/gonum/mat"
)

const (
	VocabularySize = 24
)

var Vocabulary = map[string]float64{
	"A": 0,
	"L": 1,
	"G": 2,
	"V": 3,
	"D": 4,
	"R": 5,
	"E": 6,
	"S": 7,
	"I": 8,
	"T": 9,
	"P": 10,
	"K": 11,
	"F": 12,
	"N": 13,
	"Q": 14,
	"H": 15,
	"Y": 16,
	"M": 17,
	"C": 18,
	"W": 19,
	"X": 20,
	"B": 21,
	"O": 22,
	"U": 23,
}

func Load(path string, features int, vocabulary map[string]float64) (X []*mat.Dense, Y []float64, err error) {
	var file *os.File

	if file, err = os.Open(path); err != nil {
		return nil, nil, fmt.Errorf("os.Open(%s): %w", path, err)
	}
	defer file.Close()

	sc := bufio.NewScanner(file)
	lines := make([]string, 0)

	// Read through 'tokens' until an EOF is encountered.
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}

	if err := sc.Err(); err != nil {
		return nil, nil, err
	}

	f := func(o rune) bool {
		if o == ',' || o == ' ' {
			return true
		}
		return false
	}

	X = make([]*mat.Dense, len(lines))
	Y = make([]float64, len(lines))
	var ok bool
	for i := range X {

		data := make([]float64, features)

		fields := strings.FieldsFunc(lines[i], f)

		for j, token := range fields[:features] {
			if data[j], ok = vocabulary[token]; !ok {
				return nil, nil, fmt.Errorf("invalid token: %s is not recoginzed", token)
			}
		}

		X[i] = mat.NewDense(features, 1, data)
		if Y[i], err = strconv.ParseFloat(fields[len(fields)-1], 64); err != nil {
			return nil, nil, fmt.Errorf("strconv.ParseFloat: %w", err)
		}
	}

	return
}
