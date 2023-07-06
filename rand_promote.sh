#!/bin/bash

if [ $# -ne 3 ]; then
    echo "$0 [path] [width] [percent (%)]"
    exit
fi

set -mex

path=$1
width=$2
percent=$3

total=$(($(blockdev --getsize64 $path) / 4096))
count=$(($total * $percent / 100 / $width))

./rand_mark $path $total $width $count
dd if=$path iflag=direct of=/dev/null bs=$((4 * $width))k count=$(($total / $width)) status=progress
