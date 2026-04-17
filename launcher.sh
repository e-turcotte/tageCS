#!/bin/bash

# ==============================================================================
# Configuration
# ==============================================================================
WARMUP_INSTS="50000000"
MAX_INSTS="100000000"
FAST_FORWARD="10000000000"
CPU_TYPE="X86O3CPU"

# Set parallel execution limit to 8 to avoid locking up a 16-thread machine
MAX_PARALLEL_JOBS=16

# SPEC CPU 2017 IntRate benchmarks (Excluding 500.perlbench_r and 502.gcc_r)
BENCHMARKS=(
    "500.perlbench_r"
    "502.gcc_r"
    "505.mcf_r"
    # "520.omnetpp_r"
    # "523.xalancbmk_r"
    "525.x264_r"
    "531.deepsjeng_r"
    "541.leela_r"
    # "548.exchange2_r"
    "557.xz_r"
    #"999.specrand_ir"
    # If there are additional C/C++ intrate variants you have built, add them here.
)

# Output directory for wrapper logs
LOG_DIR="./gem5_master_logs"
mkdir -p "$LOG_DIR"

echo "======================================================================"
echo " Starting parallel gem5 execution for ${#BENCHMARKS[@]} SPEC benchmarks"
echo " Configuration: Warmup=$WARMUP_INSTS | Max=$MAX_INSTS"
echo " Logs will be saved to: $LOG_DIR"
echo "======================================================================"

# ==============================================================================
# Execution via xargs
# ==============================================================================
# We export the variables so they are accessible by the subshell spawned by xargs
export WARMUP_INSTS MAX_INSTS FAST_FORWARD CPU_TYPE LOG_DIR

# The function to execute a single benchmark
run_benchmark() {
    bench=$1
    log_file="${LOG_DIR}/wrapper_${bench}.log"
    
    echo "Queueing $bench..."
    
    # Run the python script and redirect all terminal output to its own log
    python3 run_spec_se.py \
        --benchmark "$bench" \
        --cpu-type "$CPU_TYPE" \
        --bp-type TAGE \
        --warmup-insts "$WARMUP_INSTS" \
        --maxinsts "$MAX_INSTS" \
        --fast-forward "$FAST_FORWARD" \
        > "$log_file" 2>&1
        
    echo "[Done] $bench (Log: $log_file)"
}
export -f run_benchmark

# Pipe the benchmark array into xargs, limiting to MAX_PARALLEL_JOBS
printf "%s\n" "${BENCHMARKS[@]}" | xargs -n 1 -P $MAX_PARALLEL_JOBS -I {} bash -c 'run_benchmark "$@"' _ {}

echo "======================================================================"
echo " All queued benchmarks have completed."
echo "======================================================================"
