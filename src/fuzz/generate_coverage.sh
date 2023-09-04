#!/bin/bash

input_folder="../../src/fuzz/inputs/bpplus_inputs"
output_folder="../../src/fuzz/coverage_result/bpplus_coverage"
fuzz_exe="../../src/fuzz/libspark/bpplus_debug"

mkdir $output_folder

number_of_files=$(ls $input_folder | wc | awk '{print $1}')
echo "Number of input files to test: $number_of_files"

count=0

for i in $(ls $input_folder);
do
	kcov --include-path=. ./$output_folder/input_$count ./$fuzz_exe --stdout -d ./$input_folder/$i > /dev/null;
	((count++));
	echo "[++] Count of files processed: $count";
done

kcov --merge ./$output_folder/merged-output ./$output_folder/input_*