#!/bin/bash

loop=

clean() {
    set +e

    sudo dmsetup remove emux0

    sudo rmmod brd
    sudo losetup -d $loop

    sudo rmmod emux
}

trap clean EXIT
set -mex

make
sudo insmod emux.ko

disk_size=$(stat -c%s disk)
num_sectors=$(($disk_size / 512))

sudo modprobe brd rd_nr=1 rd_size=$(($disk_size / 1024))
ramdisk=/dev/ram0
loop=$(sudo losetup -f --show -b 4096 --direct-io disk)

sudo dmsetup create emux0 --table "0 $num_sectors emux 2 8 0 $loop 0 $ramdisk 0"
sudo chown $(whoami): /dev/mapper/emux0

sleep infinity
