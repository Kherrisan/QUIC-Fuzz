#!/bin/bash

FUZZER=$1     #fuzzer name (e.g., aflnet) -- this name must match the name of the fuzzer folder inside the Docker container
OUTDIR=$2     #name of the output folder
OPTIONS=$3    #all configured options -- to make it flexible, we only fix some options (e.g., -i, -o, -N) in this script
TIMEOUT=$4    #time for fuzzing
SKIPCOUNT=$5  #used for calculating cov over time. e.g., SKIPCOUNT=5 means we extract coverage after every 5 test cases

# EDIT THESE (those in "")
TARGET_DIR=${TARGET_DIR:-"google_quiche"}
COVERAGE_DIR=${COVERAGE_DIR:-"google_quiche_cov"}
INPUTS=${INPUTS:-"${WORKDIR}/google_quiche_seed"}
SERVER_CMD="/tmp/google_quiche/bazel-bin/quiche/quic_server --port=4433  --certificate_file=/tmp/google_quiche-cert.pem --key_file=/tmp/google_quiche-key.pem"
COV_BIN="/tmp/google_quiche_cov/bazel-bin/quiche/quic_server"

# Get the correct llvm version
LLVM_PROFDATA="llvm-profdata-17"
LLVM_COV="llvm-cov-17"

strstr() {
  [ "${1#*$2*}" = "$1" ] && return 1
  return 0
}

#Commands for afl-based fuzzers (e.g., aflnet, aflnwe)
if $(strstr $FUZZER "afl"); then

    # Run fuzzer-specific commands (if any)
    if [ -e ${WORKDIR}/run-${FUZZER} ]; then
        source ${WORKDIR}/run-${FUZZER}
    fi

    #Step-1. Do Fuzzing
    #Move to fuzzing folder
    cd $WORKDIR/${TARGET_DIR}/
    echo "$WORKDIR/${TARGET_DIR}/"
    timeout -k 0 --preserve-status $TIMEOUT /tmp/${FUZZER}/afl-fuzz -d -i ${INPUTS} -o $OUTDIR -N udp://127.0.0.1/4433 $OPTIONS -R $SERVER_CMD

    STATUS=$?

    #Step-2. Collect code coverage over time
    #Move to cov folder
    cd $WORKDIR/$COVERAGE_DIR

    # #The last argument passed to cov_script should be 0 if the fuzzer is afl/nwe and it should be 1 if the fuzzer is based on aflnet
    # #0: the test case is a concatenated message sequence -- there is no message boundary
    # #1: the test case is a structured file keeping several request messages
    if [ $FUZZER = "aflnwe" ]; then
        ${WORKDIR}/cov_script ${WORKDIR}/${TARGET_DIR}/${OUTDIR}/ 4433 ${SKIPCOUNT} ${WORKDIR}/${TARGET_DIR}/${OUTDIR}/cov_over_time.csv 0 $FUZZER
    else
        ${WORKDIR}/cov_script ${WORKDIR}/${TARGET_DIR}/${OUTDIR}/ 4433 ${SKIPCOUNT} ${WORKDIR}/${TARGET_DIR}/${OUTDIR}/cov_over_time.csv 1 $FUZZER
    fi

    $LLVM_COV show --instr-profile=coverage.profdata $COV_BIN --format=html -o cov_html --show-branches=count --num-threads=1 > /dev/null 2>&1
    cp -r cov_html ${WORKDIR}/${TARGET_DIR}/${OUTDIR}/cov_html/

    #Step-3. Save the result to the ${WORKDIR} folder
    #Tar all results to a file
    cd ${WORKDIR}/${TARGET_DIR}/
    tar -zcvf ${WORKDIR}/${OUTDIR}.tar.gz ${OUTDIR}

    exit $STATUS
fi