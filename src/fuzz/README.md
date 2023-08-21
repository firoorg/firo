# Fuzzing libspark

## Quickstart Guide

* In order to fuzz `firo/src/libpark` using LLVM LibFuzzer:

```
git clone -b fuzz/libspark https://github.com/hashcloak/firo.git
cd firo/src/fuzz/
export CC=hfuzz-clang
export CXX=hfuzz-clang++
```

To compile with `hfuzz-clang++`:

```
cd src/fuzz/
make <filename>
```

For example(for bpplus):
```
cd src/fuzz/
make bpplus
```
The above command will generate an instrumented binary with name `<filename>_hfuzz` (eg: bpplus_hfuzz) inside src/fuzz/libspark.

* The input Corpora for all files in src/libspark can be found in `src/fuzz/inputs/`

* To start fuzzing:

1. create a directory to save all the crahses.
2. Inside the directory run:

`hongfuzz -i <path_of_input_corpora>/<filename_inputs> -- ./<filename_hfuzz> ___FILE___`

example: 
1. `mkdir src/fuzz/results/bpplus_results && cd src/fuzz/results/bpplus_results`
2. `hongfuzz -i ../../inputs/bpplus_inputs -- ./../../libspark/bpplus_hfuzz ___FILE___`
3. To stop press `ctrl+c` or `command+c` 


### Generating a Coverage Report

1. First compile the harness with gdb flag. run `make <filename>_debug` inside src/fuzz.
2. take the input_folder as the input corpora from fuzzing or one can also create it by running: `honggfuzz -i <inputfile> -– ./<filename>_hfuzz ___FILE___ @@`

3. inside the `generate_coverage.sh` replace the input_folder, output_folder and fuzz_exe by your inpur corpora, coverage output folder and harness binary.
4. run `./generate_coverage.sh`
5. To view the result run run `firefox ./merged-output/index.html`.

6. If you are on a VM, go inside coverage output folder and then merged-output
7. run `python3 -m http.server`. This will start a http server at http://0.0.0.0:8000/
8. open your browser and paste http://0.0.0.0:8000/ to see the result.