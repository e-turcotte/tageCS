#!/bin/bash

BUILDDIR=$SPEC/benchspec/CPU/$1/build/build_base_mytest-m64.0000
LLVM=/home/eddiet/interplay/tageCS/build/bin
PYDIR=/home/eddiet/interplay/tageCS
OUTDIR=/home/eddiet/interplay/results/$1
mkdir -p $OUTDIR

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
find . -name "*.bc" | while read f; do
    base="${f%.bc}"
	$LLVM/opt -passes="dot-cfg,dot-ddg,dot-dom,dot-post-dom" $f -o /dev/null
	$LLVM/llc -relocation-model=pic -filetype=obj $f -o ${base}.o
done
$LLVM/clang $(find . -name "*.o") -o new_$EXECNAME
$LLVM/llvm-objdump -d new_$EXECNAME > new_$EXECNAME.asm
$LLVM/llvm-link $(find $OUTDIR -name "*.bc") -o $1_linked.bc
$LLVM/opt -passes="dot-callgraph" $1_linked.bc -o /dev/null
rm $1_linked.bc
#$LLVM/llvm-bolt $EXECNAME --dump-dot-all -o /dev/null &
#nm --defined-only -n $EXECNAME > symbols.txt &

python3 $PYDIR/llvmirgraph_anal_save.py > llvm.anal
python3 $PYDIR/gen_prefixes_patch.py --llvm-anal llvm.anal --bc $(find . -name "*.bc") --binary new_$EXECNAME --asm new_$EXECNAME.asm --llvm-bin $LLVM --output patch.csv
python3 $PYDIR/patchbin.py new_$EXECNAME patch.csv
$LLVM/llvm-objdump -d new_$EXECNAME.patched > new_$EXECNAME.patched.asm
#python3 $PYDIR/tagepred_anal.py tage_hits_dump.out > tage.anal
#python3 $PYDIR/gen_dbgpc_map.py --tage tage.anal --ll $1_linked.ll --binary $BUILDDIR/$EXECNAME --llvm-bin ../../tageCS/build/bin/ --output dbg_pc.map
#python3 $PYDIR/brcmp.py llvm.anal tage.anal --map dbg_pc.map > cmp.out
popd
