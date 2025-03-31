# Bug M5

## Product: Quicly (H20 project)
### Github repository: [https://github.com/h2o/quicly](https://github.com/h2o/quicly)
### Affected version: [6a903720496b8b95f8fbd1f03b7e20c9636c3221](https://github.com/h2o/quicly/commit/6a903720496b8b95f8fbd1f03b7e20c9636c3221)
### Fixed version: N/A

### Bug summary:
An assertion error cause the quicly server to crash, which can result in a Denial of Service attack.

### Bug details: 
The server is still trying to update (quicly_sentmap_update()) the st_quicly_sentmap_t in handle_ack_frame() after it goes into draining state where the callback function (quicly_sent_acked_cb) has set to  on_end_closing(). This will eventually call the on_end_closing() with the acked == 1 and cause an assertion failure.

### Attack vector:
Remote attacker (on path and off path).

### Exploitation 
1) An attack can send an Initial packet carrying a CRYPTO frame (Client Hello TLS message), PADDING frames, CONNECTION_CLOSE (1c) frame, and PADDING frames.
2) Once the server responds with an Initial packet carrying a CRYPTO frame (Server Hello TLS message), the attacker sends an Initial packet with an ACK frame to acknowledge the server's Initial packet.
3) Then, the server crashes (as described above) with an assertion error, which affects all connections on the server.

### PoC
Build the quicly server as described in the following (assumed you are in same directory as this README.md):
```bash
git clone https://github.com/h2o/quicly.git
cd quicly
git checkout 6a90372
git submodule update --init --recursive
cmake .
make -j 
cd ..

# start the server
quicly/cli -c server-cert.pem -k server-key.pem 127.0.0.1 4433 -B 012345678910
```
Open another terminal, build the replay_crash program and run with the given crash input (assumed you are in same directory as this README.md):
```bash
cd ..
make
../replay_crash quicly_crash 4433
```