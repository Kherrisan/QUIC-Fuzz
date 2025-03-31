# Bug M1

## Product: Picotls (TLS library)
### Github repository: [https://github.com/h2o/picotls](https://github.com/h2o/picotls)
### Affected version: [e4f0a27](https://github.com/h2o/picotls/commit/e4f0a27ebd1c07ebed68674258da9556fb92b46b)
### Fixed version: N/A
### Affected QUIC implementations : Picoquic, Quicly

### Bug summary:
An double-free is attempted when an processing an Initial packet carrying a TLS Client Hello message with an unexpected public key length. This results in a crash (Denial of Service attack).

### Bug details:
The program frees a memory location (```pubkey.base``` at ```picotls/lib/picotls.c:4854```) which is previously freed at ```picotls/lib/openssl.c:699```.

### Attack vector:
Remote attacker (on path).

### Exploitation 
1) An attack send an Initial packet carrying an CRYPTO frame with an unexpected public key length (shown below). Note that the public key (group x25519) uses 32 bytes (256-bit) not 65 bytes.
```C
# key share entry used in the PoC
Key Share Entry: Group: x25519, Key Exchange length: 65
```
2) Once the server receives the Initial packet, it passes the Client Hello TLS message to Picotls. Picotls tries to process the public key it received.
3) Because the public key length is not expected in ```picotls/lib/openssl.c:evp_keyex_on_exchange()```, Picotls returns ```PTLS_ALERT_DECRYPT_ERROR``` to ```picotls/lib/openssl.c:evp_keyex_exchange()```.
4) This Error will force the program to execute the code below in  ```picotls/lib/openssl.c:evp_keyex_exchange()```, where it frees pubkey.base(```outpubkey->base```) and returns.
```C
Exit:
    if (ctx != NULL)
        evp_keyex_on_exchange(&ctx, 1, NULL, ptls_iovec_init(NULL, 0));
    if (ret != 0)
        free(outpubkey->base);
    return ret;
```
4) Once the program returns to ```picotls/lib/picotls.c:server_handle_hello()```, it attempts to free ```pubkey.base``` again (shown below) and the program crashes.
```C
Exit:
    free(pubkey.base);
    if (ecdh_secret.base != NULL) {
        ptls_clear_memory(ecdh_secret.base, ecdh_secret.len);
        free(ecdh_secret.base);
    }
```

### PoC
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

> **_NOTE:_**  This PoC can also be demonstrated on Quicly server with the following command:  ```./cli -c server-cert.pem -k server-key.pem  127.0.0.1 4433 -B 012345678910 -x x25519```