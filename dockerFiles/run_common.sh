#!/bin/bash

# This is an extension of profuzzbench/scripts/execution/profuzzbench_exec_common.sh

DOCIMAGE=$1   #name of the docker image
RUNS=$2       #number of runs
SAVETO=$3     #path to folder keeping the results

FUZZER=$4     #fuzzer name (e.g., aflnet) -- this name must match the name of the fuzzer folder inside the Docker container
OUTDIR=$5     #name of the output folder created inside the docker container
OPTIONS=$6    #all configured options for fuzzing
TIMEOUT=$7    #time for fuzzing
SKIPCOUNT=$8  #used for calculating coverage over time. e.g., SKIPCOUNT=5 means we run gcovr after every 5 test cases
DELETE=$9

WORKDIR="/tmp"
TOTAL_CPU_COUNT=$(nproc)

#keep all container ids
cids=()

# check if we have enough CPU or not.

# return a list of currently assigned CPUs
get_assigned_cpus() {
	docker ps --format '{{.ID}}' | while read -r container_id; do
    	docker inspect --format '{{.HostConfig.CpusetCpus}}' "$container_id"
  	done | tr ',' '\n' | sort -n | uniq
}

# return number of CPU currently used for fuzzing in docker (assume there are no other non-fuzzing docker container)
get_assigned_cpus_count() {
	docker ps --format '{{.ID}}' | while read -r container_id; do
    	docker inspect --format '{{.HostConfig.CpusetCpus}}' "$container_id"
  	done | tr ',' '\n' | sort -n | uniq | wc -l
}

# Find the next available CPU
next_available_cpu() {
	# we keep CPU 0 for the OS
  for ((i=1; i<TOTAL_CPU_COUNT; i++)); do
    if ! get_assigned_cpus | grep -q "^${i}$"; then
      echo "$i"
      return
    fi
  done
  echo "No available CPU found" >&2
  echo "Exit now."
  exit 1
}


# the machine does not has enough CPU to do benchmark
if [ $TOTAL_CPU_COUNT -le 1 ]; then
	echo "The machine only has one CPU, not suitable for benchmarking."
	echo "Exit now."
	exit 1
fi

AVAILABLE_CPUS_COUNT=$(($TOTAL_CPU_COUNT - $(get_assigned_cpus_count) - 1))

if [ $AVAILABLE_CPUS_COUNT -lt $RUNS ]; then
	echo "The machine does not has enough CPU for $RUNS runs."
	echo "Available CPUs: $AVAILABLE_CPUS_COUNT"
	echo "Exit now."
	exit 1
fi

#create one container for each run
for i in $(seq 1 $RUNS); do
	# check which CPU to use.
	CPU_ID=$(next_available_cpu)
    id=$(docker run --log-driver=json-file --log-opt max-size=10m --log-opt max-file=1 --cpus=1 --cpuset-cpus $CPU_ID -d -it $DOCIMAGE /bin/bash -c "cd ${WORKDIR} && ./run ${FUZZER} ${OUTDIR} '-b ${CPU_ID} ${OPTIONS}' ${TIMEOUT} ${SKIPCOUNT}")
	cids+=(${id::12}) #store only the first 12 characters of a container ID
done

dlist="" #docker list
for id in ${cids[@]}; do
  	dlist+=" ${id}"
done

#wait until all these dockers are stopped
printf "\n${FUZZER^^}: Fuzzing in progress ..."
printf "\n${FUZZER^^}: Waiting for the following containers to stop: ${dlist}"
docker wait ${dlist} > /dev/null
wait

#collect the fuzzing results from the containers
printf "\n${FUZZER^^}: Collecting results and save them to ${SAVETO}"
index=1
for id in ${cids[@]}; do
	printf "\n${FUZZER^^}: Collecting results from container ${id}"
	docker cp ${id}:${WORKDIR}/${OUTDIR}.tar.gz ${SAVETO}/${OUTDIR}_${index}.tar.gz > /dev/null
	if [ ! -z $DELETE ]; then
		printf "\nDeleting ${id}"
		docker rm ${id} # Remove container now that we don't need it
	fi
	index=$((index+1))
done

printf "\n${FUZZER^^}: I am done!\n"