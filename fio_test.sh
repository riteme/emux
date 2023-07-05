#!/bin/bash

if [ $# -ne 1 ]; then
    echo "$0 [target]"
    exit
fi

set -mex

target=$1

run_fio() {
    sudo -E fio fio.conf | grep -E "IOPS|clat.*avg"
}

for rw in read write; do
    TARGET=$target NUM=1 RW=$rw SIZE=4k run_fio
    TARGET=$target NUM=1 RW=$rw SIZE=256k run_fio
    TARGET=$target NUM=16 RW=$rw SIZE=4k run_fio
done
