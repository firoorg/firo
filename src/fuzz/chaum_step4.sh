#!/bin/bash

input_folder="./results/fuzz_chaum_here/input_member"
output_folder="./results/fuzz_chaum_here/output_member"
fuzz_exe="./results/fuzz_chaum_here/chaum_fuzz_debug"

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