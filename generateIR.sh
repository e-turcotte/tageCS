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

#pc correlations
for f in *_r; do
	EXECNAME=$f
	cp $EXECNAME $OUTDIR/$EXECNAME
done

#analysis graphs
find . -name "*.o.5.precodegen.bc" | while read f; do
    base="${f%.o.5.precodegen.bc}"
	mkdir -p "$(dirname $OUTDIR/${base}.bc)"
    cp $f $OUTDIR/${base}.bc
done

popd

pushd $OUTDIR
$LLVM/llvm-objdump -d $EXECNAME > $EXECNAME.asm
$LLVM/llvm-dwarfdump --debug-line $EXECNAME > $1.dwarf
find . -name "*.bc" -print0 | xargs -0 -P 16 -I {} bash -c '
    f="{}"
    LLVM="'$LLVM'"
    base="${f%.bc}"
	$LLVM/opt -passes="dot-cfg,dot-ddg,dot-dom,dot-post-dom" $f -o /dev/null
	$LLVM/llc -relocation-model=pic -filetype=obj $f -o ${base}_wnop.o
	$LLVM/llc -skip-nop-injection -relocation-model=pic -filetype=obj $f -o ${base}_wonop.o
'

$LLVM/clang $(find . -name "*wnop.o") -o wnop_$EXECNAME
$LLVM/clang $(find . -name "*wonop.o") -o wonop_$EXECNAME
$LLVM/llvm-objdump -d wnop_$EXECNAME > wnop_$EXECNAME.asm
$LLVM/llvm-objdump -d wonop_$EXECNAME > wonop_$EXECNAME.asm
$LLVM/llvm-link $(find $OUTDIR -name "*.bc") -o $1_linked.bc
$LLVM/opt -passes="dot-callgraph" $1_linked.bc -o /dev/null
rm $1_linked.bc
#$LLVM/llvm-bolt $EXECNAME --dump-dot-all -o /dev/null &
#nm --defined-only -n $EXECNAME > symbols.txt &

python3 $PYDIR/llvmirgraph_anal.py > llvm.anal
python3 $PYDIR/gen_prefixes_patch.py --llvm-anal llvm.anal --bc $(find . -name "*.bc") --binary wnop_$EXECNAME --asm wnop_$EXECNAME.asm --llvm-bin $LLVM --output patch.csv
python3 $PYDIR/patchbin.py wnop_$EXECNAME patch.csv
$LLVM/llvm-objdump -d wnop_$EXECNAME.patched > wnop_$EXECNAME.patched.asm
#python3 $PYDIR/tagepred_anal.py tage_hits_dump.out > tage.anal
#python3 $PYDIR/gen_dbgpc_map.py --tage tage.anal --ll $1_linked.ll --binary $BUILDDIR/$EXECNAME --llvm-bin ../../tageCS/build/bin/ --output dbg_pc.map
#python3 $PYDIR/brcmp.py llvm.anal tage.anal --map dbg_pc.map > cmp.out

cp wnop_$EXECNAME.patched $BINDIR/$1.patched
cp wonop_$EXECNAME $BINDIR/$1.base
popd
