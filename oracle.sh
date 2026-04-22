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

python3 $PYDIR/gen_oracle_patch.py --hits tage_hits.dump --anal tage.anal --asm wnop_$EXECNAME.asm --patch oracle_patch.csv --fallback-patch patch.csv
python3 $PYDIR/patchbin.py wnop_$EXECNAME oracle_patch.csv --output wnop_$EXECNAME.oracle
$LLVM/llvm-objdump -d wnop_$EXECNAME.oracle > wnop_$EXECNAME.oracle.asm

cp wnop_$EXECNAME.oracle $BINDIR/$1.oracle
popd
