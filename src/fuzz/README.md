# Fuzzing libspark

## Quickstart Guide
* Dependencies
1. Install honggfuzz (https://github.com/google/honggfuzz)
```
sudo apt-get install binutils-dev libunwind-dev libblocksruntime-dev clang
git clone https://github.com/google/honggfuzz.git
cd honggfuzz
make
sudo make install
```

2. Build firo
Follow the instructions from https://github.com/firoorg/firo/tree/spark#readme

* In order to fuzz `firo/src/libpark` using LLVM LibFuzzer:

```
git clone -b spark_fuzz_blog https://github.com/hashcloak/firo.git
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
The fuzzing harness of the following spark files is availabe: aead, bech32, bpplus, chaum, coin, f4grumble, grootle, mint_transaction, schnorr and spend_transaction.

* To start fuzzing:

1. create a directory to save all the crahses.
2. Inside the directory run:
```
hongfuzz -i <path_of_input_corpora>/<filename_inputs> -- ./<filename_hfuzz> ___FILE___
```

example: 
1. `mkdir src/fuzz/bpplus_results && cd src/fuzz/bpplus_results`
2. `hongfuzz -i ../../inputs/bpplus_inputs -- ./../../libspark/bpplus_hfuzz ___FILE___`
3. To stop press `ctrl+c`

If there is no input corpora, empty corpora can be provided.

### Analyzing the crashes

If there is a crash, the reason for the crash can be found simply by running 
```
./<binary_file> <input_file>
```

Example:
```
./bpplus_hfuzz SIGABRT.PC.7ffff7a8400b.STACK.1b5b5f0067.CODE.-6.ADDR.0.INSTR.mov____0x108(%rsp),%rax
```

To debug or to do the rootcause analysis, gdb debugger can be used. to debug using gdb debugger:

1. First compile the harness using gdb flags `-g -O0 -ggdb`. To compile using gdb debugger, inside `src/fuzz` run:
```
make <filename_debug>
```
Example: 
```
make bpplus_debug
```

2. start the debugger by running:
```
gdb --args <filename_debug> <crashed_input>
```
Example:
```
gdb --args bpplus_debug SIGABRT.PC.7ffff7a8400b.STACK.1b5b5f0067.CODE.-6.ADDR.0.INSTR.mov____0x108(%rsp),%rax
```
This will start the debugger.

3. You can do heap analysis by running `heap-analysis` inside the debugger and/or `bt` for backtracing.


### Generating a Coverage Report using kcov
* Install kcov (https://github.com/SimonKagstrom/kcov/tree/master)
```
sudo apt-get install binutils-dev libssl-dev libcurl4-openssl-dev zlib1g-dev libdw-dev libiberty-dev
git clone https://github.com/SimonKagstrom/kcov.git
cd /path/to/kcov/source/dir
mkdir build
cd build
cmake ..
make
sudo make install
```
Once successfully installed, follow the below instructions to generate the code-coverage

1. First compile the harness with gdb flag. run `make <filename>_debug` inside src/fuzz to compile using gdb debugger.
2. take the input_folder as the input corpora from fuzzing or one can also create it by running: `honggfuzz -i <input_folder> -– ./<filename>_hfuzz ___FILE___ @@`. This will start the fuzzer. Kill it by `ctrl+C`. The fuzzer will generate some random inputs inside the input_folder. Since kcov will generate coverage for each input inside the input_folder, it's preffered to have only a few inputs, otherwise it will take a long time to generate the entire coverage.

3. inside the `generate_coverage.sh` replace the input_folder, output_folder and fuzz_exe by your inpur corpora, coverage output folder and harness binary.
4. run `./generate_coverage.sh`. This will generated a merged output for all the inputs present in the input_folder.
5. To view the result run run `firefox ./merged-output/index.html`.

6. alternatively or if you are on a VM, go inside coverage output folder and then merged-output
7. run `python3 -m http.server`. This will start a http server at http://0.0.0.0:8000/
8. open your browser and paste http://0.0.0.0:8000/ to see the result.

NOTE: to view the coverage for every dependent file, `generate_coverage.sh` should be in the root folder. Also, you should either delete the previous port or start the server on new port by running `python3 -m http.server <port_number>` for different files.