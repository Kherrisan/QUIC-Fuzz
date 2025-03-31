# Bug M4

## Product: Pioquic
### Github repository: [https://github.com/private-octopus/picoquic](https://github.com/private-octopus/picoquic)
### Affected version: [8f4f77f](https://github.com/private-octopus/picoquic/commit/8f4f77f854cac40d8ff1a72fa60804c83b3aed60) until [2a8f896](https://github.com/private-octopus/picoquic/commit/2a8f89691cb95cd507cb016d0b04e27319c4fce6)
### Fixed version: c0f0313
### Affected QUIC implementations : Picoquic

### Bug summary:
A NULL pointer dereference causes the server to crash, which can result in a Denial of Service attack.

### Bug details:
The program access the NULL pointer ```prefix_ctx``` at ```8f4f77f:picohttp/h3zero_common.c:1529``` after failing to match a stream ID with an existing stream context.

### Attack vector:
Remote attacker (on path).

### PoC (TO BE COMPLETED)
Build the Picoquic server as described in the following (assumed you are in same directory as this README.md):
```bash
git clone https://github.com/h2o/picotls.git
cd picotls
git submodule init
git submodule update
cmake .
make
cd ..

git clone https://github.com/private-octopus/picoquic.git
cd picoquic
cmake .
make
cd ..

# start the server (use the cert and key provided)
picoquic/picoquicdemo -R 0 -p 4433 -c server-cert.pem  -k server-key.pem
```
Open another terminal, build the replay_crash program and run with the given crash input (assumed you are in same directory as this README.md):
```bash
cd ..
make
../replay_crash picotls_crash_small 4433
```