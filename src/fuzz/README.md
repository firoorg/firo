# Fuzzing libspark

## Quickstart Guide
To quickly get started fuzzing libspark using honggfuzz:

### Build firo
- clone this repo:
```
git clone -b spark https://github.com/firoorg/firo.git
```
- Build firo: Follow instruction from https://github.com/firoorg/firo/tree/spark#readme

Once the build is successful, we have to install honggfuzz and required dependencies.

### Installing fuzzer and Dependencies
- Install honggfuzz (https://github.com/google/honggfuzz)
```
sudo apt-get install binutils-dev libunwind-dev libblocksruntime-dev clang
git clone https://github.com/google/honggfuzz.git
cd honggfuzz
make
sudo make install
```
For more information you can look at https://github.com/google/honggfuzz/blob/master/docs/USAGE.md

You might also need to install the following boost and ssl dependencies in order to compile the fuzzing harness:

```
sudo apt install libboost-dev
sudo apt install libssl-dev
sudo apt install libstdc++-12-dev
sudo apt install libboost-filesystem-dev
sudo apt install libboost-thread-dev
sudo apt install libboost-program-options-dev
sudo apt install libboost-chrono-dev
```

### Fuzzing using honggfuzz
* In order to fuzz `firo/src/libpark` using Honggfuzz:

```
cd firo/src/fuzz/
export CC=hfuzz-clang
export CXX=hfuzz-clang++
```

To compile with `hfuzz-clang++`, inside src/fuzz run:

```
make <filename>
```

For example(for bpplus):
```
make bpplus
```
The above command will generate an instrumented binary with name `<filename>_hfuzz` (eg: bpplus_hfuzz) inside src/fuzz/libspark.

The fuzzing harness of the following spark files is availabe: aead, bech32, bpplus, chaum, coin, f4grumble, grootle, mint_transaction, schnorr and spend_transaction.

* To start fuzzing:

1. create directories for input corpora and for saving all the crashes
```
mkdir input crashes
```
2. Inside the crashes directory run:
```
honggfuzz -i input -- ./libspark/<filename>_hfuzz ___FILE___
```

example: 
1. `mkdir input crashes`
2. `cd crashes`
2. `honggfuzz -i ../input -- ./../libspark/bpplus_hfuzz ___FILE___`
3. To stop press `ctrl+c`

Here we are providing an empty corpora. In case of an already available corpora, we can provide the availabe corpora.
The flag `-i` is for the input folder which we are providing `./../<filename>_hfuzz>` is the target binary which we want to fuzz.

### Analyzing the crashes

If there is a crash, the reason for the crash can be found in HONGGFUZZ.REPORT.TXT or simply by running 
```
./libspark/<binary_file> <input_file>
```

Example:
```
./libspark/bpplus_hfuzz SIGABRT.PC.7ffff7a8400b.STACK.1b5b5f0067.CODE.-6.ADDR.0.INSTR.mov____0x108(%rsp),%rax
```

To debug or to do the rootcause analysis, gdb debugger can be used. to debug using gdb debugger:

1. First compile the harness using gdb flags `-g -O0 -ggdb`. To compile using gdb debugger, inside `src/fuzz` run:
```
make <filename>_debug
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