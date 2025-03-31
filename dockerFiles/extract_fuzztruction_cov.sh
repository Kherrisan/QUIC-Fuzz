#!/bin/bash

# Define necessary paths and variables
LLVM_PROFDATA="llvm-profdata-17"
LLVM_COV="llvm-cov-17"          # Replace with your llvm-cov path
MERGED_PROF="merged_tmp.profdata"         # Temporary merged profile file

# COV_BIN="/home/kai/research/quic-fuzz/results/coverage/fuzztruction_result/fuzztruction_google_quiche/fuzztruction_google_quiche/ngtcp2_google_quiche_1.5_server_1/llvm-cov/quic_server"        # Replace with your binary path
# covfile="/home/kai/research/quic-fuzz/results/coverage/fuzztruction_result/google_quiche-fuzztruction-net.csv"   # Output file to store results

# COV_BIN="/home/kai/research/quic-fuzz/results/coverage/fuzztruction_result/fuzztruction_ngtcp2/ngtcp2_client_ngtcp2_1.5_server_1/llvm-cov/wsslserver"
# covfile="/home/kai/research/quic-fuzz/results/coverage/fuzztruction_result/ngtcp2-fuzztruction-net.csv"   # Output file to store results

# COV_BIN="/home/kai/research/quic-fuzz/results/coverage/fuzztruction_result/fuzztruction_picoquic/fuzztruction_picoquic/ngtcp2_picoquic_server_1/llvm-cov/picoquicdemo"
# covfile="/home/kai/research/quic-fuzz/results/coverage/fuzztruction_result/picoquic-fuzztruction-net.csv"   # Output file to store results

COV_BIN="/home/kai/research/quic-fuzz/results/coverage/fuzztruction_result/fuzztruction_quicly/ngtcp2_client_quicly_server_1/llvm-cov/cli"
covfile="/home/kai/research/quic-fuzz/results/coverage/fuzztruction_result/quicly-fuzztruction-net.csv"   # Output file to store results

# Check for header in the output file
if ! grep -q "^time,subject,fuzzer,run,cov_type,cov" "$covfile" 2>/dev/null; then
    echo "time,subject,fuzzer,run,cov_type,cov" > "$covfile"
fi

# Clear or create the merged profile data file
rm -f "$MERGED_PROF"
touch "$MERGED_PROF"

# Start with a header if desired (uncomment the next line if needed)
# echo "time,program,fuzzer,run_id,metric,value" > $covfile

# Loop through *.profdata files in order of their id values
for file in $(ls id:*.profdata | sort -t ':' -k 2 -n); do
    # Extract the time portion from the filename
    time=$(echo "$file" | sed -n 's/.*ts:\([0-9]*\).profdata/\1/p')

    # Merge current profdata with the accumulated merged.profdata
    $LLVM_PROFDATA merge -sparse "$MERGED_PROF" "$file" -o "$MERGED_PROF"

    # Run llvm-cov report and parse coverage data
    cov_data=$($LLVM_COV report --show-branch-summary --instr-profile="$MERGED_PROF" "$COV_BIN" --num-threads=1 | grep TOTAL | tail -n 1)
    
    # Calculate b_abs from columns 11 and 12 of cov_data
    b_abs=$(echo "$cov_data" | awk '{print $11 - $12}')
    
    # Append results to the output file
    # echo "$time,google_quiche,fuzztruction-net,10,b_abs,$b_abs" >> $covfile
    # echo "$time,ngtcp2,fuzztruction-net,10,b_abs,$b_abs" >> $covfile
    # echo "$time,picoquic,fuzztruction-net,10,b_abs,$b_abs" >> $covfile
    echo "$time,quicly,fuzztruction-net,10,b_abs,$b_abs" >> $covfile
done