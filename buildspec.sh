#!/bin/bash

HOMEDIR=/home/eddiet/interplay/
mkdir -p $HOMEDIR/results

arr=(#"500.perlbench_r" 
	 "502.gcc_r"
	 "505.mcf_r"
	 #"520.omnetpp_r"
	 #"523.xalancbmk_r"
	 "525.x264_r"
	 "531.deepsjeng_r"
	 "541.leela_r"
	 #"548.exchange2_r"
	 "557.xz_r")
	 #"999.specrand_ir")


for i in "${arr[@]}"
do
	echo "Building $i..."
	runcpu --config=spec-ir2 --action=setup $i &> $HOMEDIR/results/$i_build.log &
done

wait

for i in "${arr[@]}"
do
	echo "Analyzing and Recompiling $i..."
	$HOMEDIR/tageCS/generateIR.sh $i &> $HOMEDIR/results/$i_recomp.log &
done

wait
