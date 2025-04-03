#!/bin/bash
# run with sudo

apt -y update && apt -y upgrade
apt install -y software-properties-common
add-apt-repository ppa:ubuntu-toolchain-r/test
apt -y update && apt -y upgrade
apt install -y build-essential git graphviz clang-12 llvm-12 llvm-12-dev llvm-12-tools openssl libssl-dev graphviz-dev libcap-dev lsof wget gpg libsqlite3-dev libelf-dev libc6-dbg gettext libgnutls28-dev apt-utils libtool gettext-base cmake-curses-gui libcurl4-openssl-dev libjson-c-dev libpcre2-dev

wget https://apt.llvm.org/llvm-snapshot.gpg.key
gpg --dearmor -o /usr/share/keyrings/llvm-archive-keyring.gpg llvm-snapshot.gpg.key
echo "deb [signed-by=/usr/share/keyrings/llvm-archive-keyring.gpg] http://apt.llvm.org/$(lsb_release -cs)/ llvm-toolchain-$(lsb_release -cs)-17 main" | tee /etc/apt/sources.list.d/llvm.list
apt -y update && apt -y upgrade
apt install llvm-17 llvm-17-dev llvm-17-tools clang-17 lld-17

export LLVM_CONFIG=/usr/bin/llvm-config-17
ln -s /usr/bin/clang-17 /usr/bin/clang && ln -s /usr/bin/clang-17 /usr/bin/clang++

# compile the QUIC-Fuzz
cd aflnet/
wget https://www.openssl.org/source/openssl-3.0.2.tar.gz
tar xzvf openssl-3.0.2.tar.gz
cd openssl-3.0.2
./Configure linux-x86_64 no-shared
make -j
cd ..
make clean all -j
cd aflnet/llvm_mode
make -j
cd ../SnapFuzz/SaBRe/plugins
ln -sf ../../snapfuzz snapfuzz
cd ..
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=RELEASE -DSF_MEMFS=OFF -DSF_STDIO=ON -DSF_SLEEP=ON -DSF_SMARTDEFER=ON ..
make -j
cd ../../../
ln -sf SnapFuzz/SaBRe/build/sabre sabre
ln -sf SnapFuzz/SaBRe/build/plugins/snapfuzz/libsnapfuzz.so libsnapfuzz.so
cd ..

# dir to store results
mkdir results

# sudo su
# echo core >/proc/sys/kernel/core_pattern
# exit