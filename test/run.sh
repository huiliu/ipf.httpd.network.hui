#!/bin/bash

filter=../filter

for file in 10 30 60
do
    memrm --servers=localhost '$1$--------$CW7TIEz2J5jB8j/v3z3wQ.'
    cat $file | $filter &> log
    echo "$file seconds test result: `grep -i error log`"
done
