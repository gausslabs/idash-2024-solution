# IDASH 2024

## Setup

### No Docker

1. Make sure you have Go 1.23.1 or greated installed.
2. `$ go mod tidy` to download and install all the dependencies.
3. `$ go build solution_1.go`
4. `$ go build solution_2.go`
5. See `Running the Solution`.

### With Docker

```
$ docker build -t gausslabs_idash2024 .
$ docker run -it gausslabs_idash2024
$ cd ../root/idash2024
$ go mod tidy
$ go build solution_1.go
$ go build solution_2.go
```

### Input Format & Location

By default the excecutable will look for `./data/example_AA_sequences.list`, but a custom path can be given (see `Optional Flags`).
File format is expected to be identical to `example_AA_sequences.list`.

## Running the Solution

Once the previous steps have been followed:

1. `$ taskset -c 0-3 ./solution_1`: slower (13min on i9-12900K 4 threads) on but more precise (~1e-3.5 error, 100% CT vs. PT Accuracy) solution.
2. `$ taskset -c 0-3 ./solution_2`: faster (9min i9-12900K 4 threads) but less precise solution (~1e0 error, 92% CT vs. PT Accuracy) solution.

### Optional Flags

- `-i=<data_path>`: custom path for the input data.
- `-dummy`: use dummy boostrapping.
- `-debug`: print intermediate values.
- `-verify`: saves ideal result in `./result/prec_plain.csv`, print accuracy and average error of encrypted vs. plaintext circuit.

## Output

The result of the encrypted computation is written in `./result/pred_enc.csv`.
The file contains a `lib.NbSamples` x `lib.Classes` matrix, with one row per line.
