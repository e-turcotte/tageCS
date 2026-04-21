#!/bin/bash

BUILDDIR=$SPEC/benchspec/CPU/$1/build/build_base_mytest-m64.0000
LLVM=/home/eddiet/interplay/tageCS/build/bin
PYDIR=/home/eddiet/interplay/tageCS
OUTDIR=/home/eddiet/interplay/results/$1
BINDIR=/home/eddiet/interplay/bins/
mkdir -p $OUTDIR
mkdir -p $BINDIR

EXECNAME=tmp


pushd $BUILDDIR
for f in *_r; do
	EXECNAME=$f
done
popd

pushd $OUTDIR

python3 $PYDIR/llvmirgraph_anal.py --no-destructive-alias --no-constructive-alias> llvm.anal
python3 $PYDIR/gen_prefixes_patch.py --llvm-anal llvm.anal --bc $(find . -name "*.bc") --binary wnop_$EXECNAME --asm wnop_$EXECNAME.asm --llvm-bin $LLVM --output patch.csv
python3 $PYDIR/patchbin.py wnop_$EXECNAME patch.csv
python3 $PYDIR/patchbin.py wnop_$EXECNAME baseline_patch.csv --output wnop_$EXECNAME.base
python3 $PYDIR/patchbin.py wnop_$EXECNAME rand_patch.csv --output wnop_$EXECNAME.rand
$LLVM/llvm-objdump -d wnop_$EXECNAME.patched > wnop_$EXECNAME.patched.asm
$LLVM/llvm-objdump -d wnop_$EXECNAME.base > wnop_$EXECNAME.base.asm
$LLVM/llvm-objdump -d wnop_$EXECNAME.rand > wnop_$EXECNAME.rand.asm

cp wnop_$EXECNAME.patched $BINDIR/$1.patched
cp wnop_$EXECNAME.base $BINDIR/$1.base
cp wnop_$EXECNAME.rand $BINDIR/$1.rand
cp wonop_$EXECNAME $BINDIR/$1.orig
popd
