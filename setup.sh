#!/bin/bash

disk_loop=
cache_loop=
dmesg_pid=

clean() {
    set +e

    sudo dmsetup remove emux0
    sudo losetup -d $disk_loop
    sudo losetup -d $cache_loop
    sudo umount tmpfs
    sudo rmmod emux
    sudo kill $dmesg_pid
}

trap clean EXIT
set -mex

sudo dmesg --human --nopager --force-prefix --kernel --follow-new &
dmesg_pid=$!

make
sudo insmod emux.ko

disk_size=$(stat -c%s disk)
num_sectors=$(($disk_size / 512))

mkdir -p tmpfs
sudo mount -t tmpfs -o noatime,lazytime,defaults tmpfs tmpfs
sudo dd if=/dev/zero of=tmpfs/cache bs=1M count=$(($disk_size / 1024 / 1024)) status=progress
disk_loop=$(sudo losetup -f --show -b 4096 --direct-io disk)
cache_loop=$(sudo losetup -f --show -b 4096 tmpfs/cache)

sudo dmsetup create emux0 --table "0 $num_sectors emux 2 8 0 $disk_loop 0 $cache_loop 0"
sudo chown $(whoami): /dev/mapper/emux0 $disk_loop $cache_loop

sleep infinity
