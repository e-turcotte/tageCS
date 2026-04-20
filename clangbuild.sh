#!/bin/sh

build=`pwd`/build
llvm=`pwd`/llvm-tageassist
mkdir -p $build

cmake -G "Unix Makefiles" -S $llvm/llvm -B $build -DLLVM_ENABLE_PROJECTS="clang;lld;bolt"

cmake --build $build -j20
