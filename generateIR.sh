#!/bin/bash

BUILDDIR=$SPEC/benchspec/CPU/$1/build/build_base_mytest-m64.0000
LLVM=/home/eddiet/interplay/tageCS/build/bin
OUTDIR=/home/eddiet/interplay/results/$1
mkdir -p $OUTDIR


pushd $BUILDDIR

#pc correlations
for f in *_r; do
	objdump -d $f > $OUTDIR/$1.asm
	$LLVM/llvm-dwarfdump --debug-line $f > $OUTDIR/$1.dwarf
done

#analysis graphs
for f in *.o; do
    base="${f%.o}"
    $LLVM/llvm-objcopy --dump-section=.llvmbc="$OUTDIR/${base}.bc" "$f"
done

popd

pushd $OUTDIR
$LLVM/llvm-link *.bc -o $1_linked.bc
$LLVM/opt -passes="dot-callgraph,dot-cfg,dot-ddg,dot-dom,dot-post-dom" $1_linked.bc -o /dev/null
popd
