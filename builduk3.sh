#!/bin/bash

#CC=gcc-7 ./build-rr.sh $@ hw
cd demo
../rumprun-firecracker/bin/x86_64-rumprun-netbsd-gcc -g hello.c -o hello
../rumprun-firecracker/bin/rumprun-bake hw_virtio sleep.bin hello
cd ..
