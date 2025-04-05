# 🤖 QUIC-Fuzz
Code release for [QUIC-Fuzz: An Effective Greybox Fuzzer For The QUIC Protocol](https://arxiv.org/abs/2503.19402).

An Extension of AFLNet to fuzz QUIC.
This is tested on Ubuntu 22.04.

## 💾 Installation
### "QUIC" installtaion using the build script. This will install QUIC-Fuzz.
```bash
sudo ./setup.sh
```
### Install dependencies.
```bash
sudo apt update && sudo apt upgrade
sudo apt install software-properties-common
sudo add-apt-repository ppa:ubuntu-toolchain-r/test
sudo apt update && sudo apt upgrade
sudo apt install build-essential git graphviz clang-12 llvm-12 llvm-12-dev llvm-12-tools openssl libssl-dev graphviz-dev libcap-dev lsof wget gpg libsqlite3-dev libelf-dev libc6-dbg gettext libgnutls28-dev apt-utils libtool gettext-base cmake-curses-gui libcurl4-openssl-dev libjson-c-dev libpcre2-dev

wget https://apt.llvm.org/llvm-snapshot.gpg.key
gpg --dearmor -o /usr/share/keyrings/llvm-archive-keyring.gpg llvm-snapshot.gpg.key
echo "deb [signed-by=/usr/share/keyrings/llvm-archive-keyring.gpg] http://apt.llvm.org/$(lsb_release -cs)/ llvm-toolchain-$(lsb_release -cs)-17 main" | tee /etc/apt/sources.list.d/llvm.list
sudo apt update && sudo apt upgrade

export LLVM_CONFIG=/usr/bin/llvm-config-17
ln -s /usr/bin/clang-17 /usr/bin/clang && ln -s /usr/bin/clang-17 /usr/bin/clang++
```

### Compile QUIC-Fuzz.
```bash
git clone https://github.com/QUICTester/QUIC-Fuzz.git quic-fuzz
cd quic-fuz/aflnet
wget https://www.openssl.org/source/openssl-3.0.2.tar.gz
tar xzvf openssl-3.0.2.tar.gz
cd openssl-3.0.2
./Configure linux-x86_64 no-shared
make -j
cd ..
make clean all -j
cd llvm_mode
make -j
cd ../SnapFuzz/SaBRe/plugins
ln -sf ../../snapfuzz snapfuzz
cd ..
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=RELEASE -DSF_MEMFS=OFF -DSF_STDIO=ON -DSF_SLEEP=ON -DSF_SMARTDEFER=OFF .. && make -j && mv plugins/snapfuzz/libsnapfuzz.so  plugins/snapfuzz/libsnapfuzz_no_snap.so
cmake -DCMAKE_BUILD_TYPE=RELEASE -DSF_MEMFS=OFF -DSF_STDIO=ON -DSF_SLEEP=ON -DSF_SMARTDEFER=ON .. && make -j
cd ../../../
ln -sf SnapFuzz/SaBRe/build/sabre sabre && ln -sf SnapFuzz/SaBRe/build/plugins/snapfuzz/libsnapfuzz.so libsnapfuzz.so && ln -sf SnapFuzz/SaBRe/build/plugins/snapfuzz/libsnapfuzz_no_snap.so libsnapfuzz_no_snap.so
cd ../
mkdir results
```

### Additional configurations for the AFLNet engine.
```bash
sudo su
echo core >/proc/sys/kernel/core_pattern
exit
```

## 💻 Fuzzing a new QUIC server:
In order to fuzz a new QUIC server, QUIC-Fuzz require a seed (same as AFLNet). There are few configurations you need to set before capturing the seed using the method shown in [AFLNet README.md](./aflnet/README.md):
1) Hardcode the Source Connection ID (SCID) of the server.
2) Start the packet number from 0 on both, client and server. 
3) Hardcode the Handshake secret and Traffic secret on the client and server.
4) Hardcode the handshake (Finished) verify data on the client and server.

These configurations can improve the fuzzer performance and stability. Once these are set, you can now compile and test the servers. We have include 6 examples in [./dockerFiles](./dockerFiles/), please read [./dockerFiles/README.md](./dockerFiles/README.md).


## 🏅 Security Advisory Credit from QUIC developers
This project has been acknowledged for contributing to the discovery and responsible disclosure of security vulnerabilities.

- https://github.com/h2o/picotls/security/advisories/GHSA-w7c8-wjx9-vvvv
- https://github.com/h2o/quicly/security/advisories/GHSA-mp3c-h5gg-mm6p
- https://www.privateoctopus.com/2024/11/17/thanks-to-quictester-quic-fuzz.html

We are proud to contribute to the security and robustness of open-source ecosystems through responsible vulnerability discovery and coordinated disclosure.