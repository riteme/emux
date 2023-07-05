#!/bin/bash

if [ $# -ne 2 ]; then
    echo "$0 [path] [percent%]"
    exit
fi

set -mex

path=$1
percent=$2

total=$(($(blockdev --getsize64 $path) / 4096))
count=$(($total * $percent / 100))

./rand_mark $path $total $count
dd if=$path iflag=direct of=/dev/null bs=4k count=$total status=progress
