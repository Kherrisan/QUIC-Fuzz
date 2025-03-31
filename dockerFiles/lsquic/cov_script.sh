#!/bin/bash

folder=$1   #fuzzer result folder
pno=$2      #port number
step=$3     #step to skip coverage extraction and outputting data to covfile
            #e.g., step=5 means we extract coverage after every 5 test cases
covfile=$4  #path to coverage file
fmode=$5    #file mode -- structured or not
            #fmode = 0: the test case is a concatenated message sequence -- there is no message boundary
            #fmode = 1: the test case is a structured file keeping several request messages
fuzzer=$6   #fuzzer name/path

# EDIT THESE (those in "")
# change the server path to the one with cov patch
SERVER_CMD="/tmp/lsquic_cov/bin/http_server -Q hq-29 -s 127.0.0.1:4433 -c www.example.com,/tmp/server-cert.pem,/tmp/server-key.pem"
COV_BIN="/tmp/lsquic_cov/bin/http_server"

# store the llvm-profdata and llvm-cov names
LLVM_PROFDATA="llvm-profdata-17"
LLVM_COV="llvm-cov-17"
export LLVM_PROFILE_FILE="profile-%p.profraw"

#delete the existing coverage file
rm $covfile; touch $covfile

#clear coverage data
rm *.profraw # when we use llvm source code base coverage

#output the header of the coverage file which is in the CSV format
#Time: timestamp, l_per/b_per and l_abs/b_abs: line/branch coverage in percentage and absolutate number
echo "Time,l_per,l_abs,b_per,b_abs" >> $covfile

#files stored in replayable-* folders are structured
#in such a way that messages are separated
if [ $fmode -eq "1" ]; then
  testdir="replayable-queue"
  replayer="/tmp/$fuzzer/aflnet-replay"
else
  testdir="queue"
  replayer="afl-replay"
fi

isFirst=0
#process initial seed corpus first
for f in $(find $folder/$testdir/ -name "*.raw" | grep -v "\.secret$" | sort); do 
  time=$(stat -c %Y $f)

  #terminate running server(s)
  kill -9 $(lsof -t -i:$pno)

  timeout -k 1 -s SIGUSR1 3s $SERVER_CMD > /dev/null 2>&1 &
  sleep 1
  $replayer $f QUIC $pno > /dev/null 2>&1
  
  wait
  # llvm source code-based coverage
  if [ "$isFirst" == "0" ]; then 
    $LLVM_PROFDATA merge -sparse *.profraw -o coverage.profdata --num-threads=1
    isFirst=1
  else
    $LLVM_PROFDATA merge -sparse *.profraw coverage.profdata -o coverage.profdata --num-threads=1
  fi
  rm *.profraw
  cov_data=$($LLVM_COV report --show-branch-summary --instr-profile=coverage.profdata $COV_BIN  --num-threads=1 | grep TOTAL | tail -n 1)
  l_per=$(echo "$cov_data" | awk '{print $10}')
  l_abs=$(echo "$cov_data" | awk '{print $8-$9}')
  b_per=$(echo "$cov_data" | awk '{print $13}')
  b_abs=$(echo "$cov_data" | awk '{print $11-$12}')
  
  echo "$time,$l_per,$l_abs,$b_per,$b_abs" >> $covfile
done

#process fuzzer-generated testcases
count=0
for f in $(find $folder/$testdir/ -name "id*" | grep -v "\.secret$" | sort); do 
  time=$(stat -c %Y $f)

  #terminate running server(s)
  kill -9 $(lsof -t -i:$pno)
   
  timeout -k 1 -s SIGUSR1 3s $SERVER_CMD > /dev/null 2>&1 &
  sleep 1
  $replayer $f QUIC $pno > /dev/null 2>&1

  wait
  count=$(expr $count + 1)
  rem=$(expr $count % $step)
  if [ "$rem" != "0" ]; then continue; fi
  # llvm source code based coverage
  if [ "$isFirst" == "0" ]; then 
    $LLVM_PROFDATA merge -sparse *.profraw -o coverage.profdata --num-threads=1
    isFirst=1
  else
    $LLVM_PROFDATA merge -sparse *.profraw coverage.profdata -o coverage.profdata --num-threads=1
  fi
  rm *.profraw
  cov_data=$($LLVM_COV report --show-branch-summary --instr-profile=coverage.profdata $COV_BIN --num-threads=1 | grep TOTAL | tail -n 1)
  l_per=$(echo "$cov_data"  | awk '{print $10}')
  l_abs=$(echo "$cov_data"  | awk '{print $8-$9}')
  b_per=$(echo "$cov_data"  | awk '{print $13}')
  b_abs=$(echo "$cov_data"  | awk '{print $11-$12}')
  
  echo "$time,$l_per,$l_abs,$b_per,$b_abs" >> $covfile
done

#ouput cov data for the last testcase(s) if step > 1
if [[ $step -gt 1 ]]
then
  time=$(stat -c %Y $f)
  # llvm source code based coverage
  if [ "$isFirst" == "0" ]; then 
    $LLVM_PROFDATA merge -sparse *.profraw -o coverage.profdata --num-threads=1
    isFirst=1
  else
    $LLVM_PROFDATA merge -sparse *.profraw coverage.profdata -o coverage.profdata --num-threads=1
  fi
  rm *.profraw
  cov_data=$($LLVM_COV report --show-branch-summary --instr-profile=coverage.profdata $COV_BIN --num-threads=1 | grep TOTAL | tail -n 1)
  l_per=$(echo "$cov_data"  | awk '{print $10}')
  l_abs=$(echo "$cov_data"  | awk '{print $8-$9}')
  b_per=$(echo "$cov_data"  | awk '{print $13}')
  b_abs=$(echo "$cov_data"  | awk '{print $11-$12}')
  
  echo "$time,$l_per,$l_abs,$b_per,$b_abs" >> $covfile
fi