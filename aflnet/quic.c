#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "alloc-inl.h"
#include "debug.h"

// QUIC-Fuzz: ADDED HERE to decrypt Quic packet.
#include <openssl/kdf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/aes.h>
#include <errno.h>

#include "quic.h"

// // // extern from the afl-fuzz.c
// extern u8 is_gen_train_data;
u8 is_quic = 0;
u8 is_retry = 0;
u8 is_fuzz_with_dec_enc = 0;
u8 is_gen_train_data = 0;
u8 is_replay = 0;

// store quic information 
struct quic_conn_info quic_info;

// print raw data in byte string (use for debugging)
void print_byte_string(unsigned char *byte_str, unsigned int byte_str_size){
    for (size_t i=0; i<byte_str_size; i++){
        printf("%02x ", byte_str[i]);
    }

    printf("\n");
}

// print raw data in byte string to a file (use for debugging)
void print_byte_string_to_log(const char *file, const char *start_extra, const char *end_extra, unsigned char *byte_str, unsigned int byte_str_size){
    FILE *log = fopen(file, "a");

    if(start_extra != NULL){
        fprintf(log, "%s", start_extra);
    }
    
    for (size_t i=0; i<byte_str_size; i++){
        fprintf(log, "%02x ", byte_str[i]);
    }

    fprintf(log, "\n");

    if(end_extra != NULL){
        fprintf(log, "%s", end_extra);
    }

    fclose(log);
}

// reset some variables after each run
void reset_quic_info(){
    quic_info.client_expected_initial_num = 0;
    quic_info.client_expected_handshake_num = 0;
    quic_info.client_expected_traffic_num = 0;
    quic_info.server_expected_initial_num = 0;
    quic_info.server_expected_handshake_num = 0;
    quic_info.server_expected_traffic_num = 0;
}

// Initialise the variables
void init_quic_info(){
    quic_info.quic_version = No_Assigned;
    quic_info.is_derived_handshake_traffic_secret = 0;
    quic_info.initial_secret = NULL;
    quic_info.initial_secret_count = 0;
    quic_info.current_initial_secret = NULL;
    quic_info.stop_derive_initial_secret = 0;
    quic_info.one_rtt_dcid = NULL;
    quic_info.one_rtt_dcid_count = 0;
    quic_info.one_rtt_scid = NULL;
    quic_info.one_rtt_scid_count = 0;

    quic_info.client_expected_initial_num = 0;
    quic_info.client_expected_handshake_num = 0;
    quic_info.client_expected_traffic_num = 0;
    quic_info.server_expected_initial_num = 0;
    quic_info.server_expected_handshake_num = 0;
    quic_info.server_expected_traffic_num = 0;
}

// free the quic_info memory
void free_quic_info(){
    if(quic_info.initial_secret) ck_free(quic_info.initial_secret);
    if(quic_info.one_rtt_dcid) ck_free(quic_info.one_rtt_dcid);
    if(quic_info.one_rtt_scid) ck_free(quic_info.one_rtt_scid);
}

// stop to derive Initial packet after this
void set_stop_derive_initial_secret(){
    quic_info.stop_derive_initial_secret = 1;
}

void add_cid(struct connection_id **cid_struct_array, unsigned int *cid_struct_array_size, unsigned char *cid, unsigned int len){
    // make sure the cid len does not exceed the max
    if(len <= CONN_ID_MAX_SIZE){

        // if this is the first cid, we just add it in
        if(*cid_struct_array_size == 0 && *cid_struct_array == NULL){
            *cid_struct_array = (struct connection_id *)ck_alloc(sizeof(struct connection_id));

            if(*cid_struct_array == NULL){
                PFATAL("Unable to allocate space for cid_struct_array");
            }

            memcpy((*cid_struct_array)[*cid_struct_array_size].cid, cid, len);
            (*cid_struct_array)[*cid_struct_array_size].cid_len = len;
            *cid_struct_array_size++;
        
        // if it is not, we compare and add it if it is new
        }else{
            unsigned int is_exist = 0;

            // compare
            for(int i=0; i<*cid_struct_array_size; i++){
                if((*cid_struct_array)[i].cid_len == len){
                    if(memcmp((*cid_struct_array)[i].cid, cid, len) == 0){
                        is_exist = 1;
                        break;
                    }
                }
            }
            
            if(is_exist == 0){
                *cid_struct_array = (struct connection_id *)ck_realloc(*cid_struct_array, ((*cid_struct_array_size)+1)*sizeof(struct connection_id));

                if(*cid_struct_array == NULL){
                    PFATAL("Unable to re-allocate space for cid_struct_array");
                }

                memcpy((*cid_struct_array)[*cid_struct_array_size].cid, cid, len);
                (*cid_struct_array)[*cid_struct_array_size].cid_len = len;
                *cid_struct_array_size++;
            }
            
        }
    }
}

// Variable-Length Integer Decoding to get the payload length (including Packet Number)
// Appendix A.1, RFC 9000 (Figure 45)
// return the value
unsigned int variable_len_int_decode(unsigned char *mem, unsigned int *mem_count, unsigned int *mem_size, unsigned int *cur_end, unsigned char* buf, unsigned int *byte_count, unsigned int buf_size){
    // The length of variable-length integers is encoded in the
    // first two bits of the first byte.
    unsigned int v = mem[*mem_count];
    unsigned int prefix = v >> 6;
    unsigned int length = 1 << prefix;

    // Once the length is known, remove these bits and read any
    // remaining bytes.
    v = v & 0x3f;

    while(length-- > 1){
        if(cur_end == NULL && buf == NULL && byte_count == NULL && buf_size == NULL){
            // use for decoding variable length without the need of memcpy (mainly in quic.c)
            (*mem_count)++;

            if(*mem_count < *mem_size){
                v = (v << 8) + mem[(*mem_count)];
            }
        }else if(byte_count != NULL && buf_size != NULL){
            // copy the byte into mem from buf when parsing the packet (mainly in aflnet.c)
            if(*byte_count < buf_size){
                (*mem_count)++;

                // make sure mem have enough space
                if(*mem_count == *mem_size) {
                    //enlarge the mem buffer
                    *mem_size = (*mem_size) * 2;
                    mem=(char *)ck_realloc(mem, *mem_size);
                }

                if(cur_end != NULL){
                    // increase the end of the region when extracting the seed
                    (*cur_end)++;  
                }
                
                memcpy(&mem[*mem_count], buf + (*byte_count)++, 1);
                v = (v << 8) + mem[(*mem_count)];
            }
        }
    }

    return v;
}

// need to use server Initial key, iv to decrypt the server's packet 
// return 0 (success), 1 (fail)
int derive_secret(int is_client, enum PacketType packet_type){
    struct endpoint_secret *endpoint_secret;

    // to do: add pointer to server or client initial
    if(is_client){
        switch(packet_type){
            case Initial:
                endpoint_secret = &quic_info.current_initial_secret->client_initial_secret;
                break;
            case Handshake:
                endpoint_secret = &quic_info.client_handshake_secret;
                break;
            case ZeroRTT:
            case OneRTT:
                endpoint_secret = &quic_info.client_traffic_secret;
                break;
            default:
                endpoint_secret = NULL;
                break;
        }
    }else{
        switch(packet_type){
            case Initial:
                endpoint_secret = &quic_info.current_initial_secret->server_initial_secret;
                break;
            case Handshake:
                endpoint_secret = &quic_info.server_handshake_secret;
                break;
            case ZeroRTT:
            case OneRTT:
                endpoint_secret = &quic_info.server_traffic_secret;
                break;
            default:
                endpoint_secret = NULL;
                break;
        }
    }

	// Key derivation using EVP_KDF
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);

	if(kdf == NULL){
        return 1;
    }

    EVP_KDF_CTX *kdf_ctx = EVP_KDF_CTX_new(kdf);
    OSSL_PARAM params[5], *p = params;

    // derive Initial secret
    if(packet_type == Initial && quic_info.current_initial_secret->is_derived_initial_secret == 0){
        // unsigned char rfc_cid[] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};

        /* Build up the parameters for the derivation  (HKDF-Extract)*/
        *p++ = OSSL_PARAM_construct_utf8_string("mode", "EXTRACT_ONLY", (size_t)12);
        *p++ = OSSL_PARAM_construct_utf8_string("digest", "SHA256", (size_t)6);

        if(quic_info.quic_version == Version_1){
            *p++ = OSSL_PARAM_construct_octet_string("salt", initial_salt, sizeof(initial_salt));
        }else if(quic_info.quic_version == Draft_29){
            *p++ = OSSL_PARAM_construct_octet_string("salt", initial_salt_draft_29, sizeof(initial_salt_draft_29));
        }

        // *p++ = OSSL_PARAM_construct_octet_string("key", rfc_cid, quic_info.client_first_dest_conn_id_length);
        *p++ = OSSL_PARAM_construct_octet_string("key", quic_info.current_initial_secret->client_first_dest_conn_id, quic_info.current_initial_secret->client_first_dest_conn_id_len);
        *p = OSSL_PARAM_construct_end();

        // derive Initial secret
        if(EVP_KDF_derive(kdf_ctx, &quic_info.current_initial_secret->initial_secret, SECRET_SIZE, params) <= 0){
            WARNF("Not able to derive initial secret.\n");
            EVP_KDF_CTX_free(kdf_ctx);
            EVP_KDF_free(kdf);
            return 1;
        }

        quic_info.current_initial_secret->is_derived_initial_secret = 1;
    }
    
    // get specific endpoint Initial secret
    if(packet_type == Initial){
        unsigned char *endpoint_label;
        unsigned int endpoint_label_size;

        if(is_client){
            endpoint_label = client_label;
            endpoint_label_size = sizeof(client_label);
        }else{
            endpoint_label = server_label;
            endpoint_label_size = sizeof(server_label);
        }

        // expand endpoint initial secret
        p = params;
        /* Build up the parameters for the derivation (HKDF-Expand)*/
        *p++ = OSSL_PARAM_construct_utf8_string("mode", "EXPAND_ONLY", (size_t)11);
        *p++ = OSSL_PARAM_construct_utf8_string("digest", "SHA256", (size_t)6);
        *p++ = OSSL_PARAM_construct_octet_string("info", endpoint_label, endpoint_label_size);
        *p++ = OSSL_PARAM_construct_octet_string("key", quic_info.current_initial_secret->initial_secret, SECRET_SIZE);
        *p = OSSL_PARAM_construct_end();

        // expand endpoint initial secret
        if(EVP_KDF_derive(kdf_ctx, endpoint_secret->secret, SECRET_SIZE, params) <= 0){
            WARNF("Not able to expand %s initial secret.\n", (is_client == 1)? "client" : "server");
            EVP_KDF_CTX_free(kdf_ctx);
            EVP_KDF_free(kdf);
            return 1;
        }
    // get specific endpoint Handshake secret
    }else if(packet_type == Handshake){
        memcpy(endpoint_secret->secret, handshake_secret, SECRET_SIZE);
    // get specific endpoint Traffic secret
    }else if(packet_type == OneRTT){
        memcpy(endpoint_secret->secret, traffic_secret, SECRET_SIZE);
    }else{
        return 1;
    }

    p = params;
    /* Build up the parameters for the derivation (HKDF-Expand)*/
    *p++ = OSSL_PARAM_construct_utf8_string("mode", "EXPAND_ONLY", (size_t)11);
    *p++ = OSSL_PARAM_construct_utf8_string("digest", "SHA256", (size_t)6);
    *p++ = OSSL_PARAM_construct_octet_string("info", quic_key_label, sizeof(quic_key_label));
    *p++ = OSSL_PARAM_construct_octet_string("key", endpoint_secret->secret, SECRET_SIZE);
    *p = OSSL_PARAM_construct_end();

    // expand endpoint initial key
    if(EVP_KDF_derive(kdf_ctx, endpoint_secret->key, KEY_SIZE, params) <= 0){
        WARNF("Not able to expand %s initial key.\n", (is_client == 1)? "client" : "server");
        EVP_KDF_CTX_free(kdf_ctx);
        EVP_KDF_free(kdf);
        return 1;
    }

    p = params;
    /* Build up the parameters for the derivation (HKDF-Expand)*/
    *p++ = OSSL_PARAM_construct_utf8_string("mode", "EXPAND_ONLY", (size_t)11);
    *p++ = OSSL_PARAM_construct_utf8_string("digest", "SHA256", (size_t)6);
    *p++ = OSSL_PARAM_construct_octet_string("info", quic_iv_label, sizeof(quic_iv_label));
    *p++ = OSSL_PARAM_construct_octet_string("key", endpoint_secret->secret, SECRET_SIZE);
    *p = OSSL_PARAM_construct_end();

    // expand endpoint initial iv
    if(EVP_KDF_derive(kdf_ctx, endpoint_secret->iv, IV_SIZE, params) <= 0){
        WARNF("Not able to expand %s initial iv.\n", (is_client == 1)? "client" : "server");
        EVP_KDF_CTX_free(kdf_ctx);
        EVP_KDF_free(kdf);
        return 1;
    }

    p = params;
    /* Build up the parameters for the derivation (HKDF-Expand)*/
    *p++ = OSSL_PARAM_construct_utf8_string("mode", "EXPAND_ONLY", (size_t)11);
    *p++ = OSSL_PARAM_construct_utf8_string("digest", "SHA256", (size_t)6);
    *p++ = OSSL_PARAM_construct_octet_string("info", quic_hp_label, sizeof(quic_hp_label));
    *p++ = OSSL_PARAM_construct_octet_string("key", endpoint_secret->secret, SECRET_SIZE);
    *p = OSSL_PARAM_construct_end();

    // expand server initial hp
    if(EVP_KDF_derive(kdf_ctx, endpoint_secret->hp, HP_SIZE, params) <= 0){
        WARNF("Not able to expand %s initial hp.\n", (is_client == 1)? "client" : "server");
        EVP_KDF_CTX_free(kdf_ctx);
        EVP_KDF_free(kdf);
        return 1;
    }

    // EVP_KDF_derive(kdf_ctx, quic_info.initial_secret, sizeof(quic_info.initial_secret), NULL);		
    EVP_KDF_CTX_free(kdf_ctx);
    EVP_KDF_free(kdf);
    
    return 0;
}

// write all secret to a file
// so that afl-replay can re-encrypt the crashing inputs
void write_secrets_to_file(u8 *filename){
    s32 fd = open(filename, O_WRONLY | O_CREAT, 0600);
    if (fd < 0) PFATAL("Unable to create file '%s'", filename);

    u32 secret_size = 0;
    u32 len_count = 0;
    u8 *secret = NULL; 

    if(quic_info.current_initial_secret != NULL){
        // add Initial secrets
        secret_size = (SECRET_SIZE + KEY_SIZE + IV_SIZE + HP_SIZE)*2;
        secret = (u8 *)ck_alloc(secret_size);

        // client Initial secret
        memcpy(secret, &(quic_info.current_initial_secret->client_initial_secret.secret), SECRET_SIZE);
        len_count += SECRET_SIZE;
        memcpy(secret + len_count, &(quic_info.current_initial_secret->client_initial_secret.key), KEY_SIZE);
        len_count += KEY_SIZE;
        memcpy(secret + len_count, &(quic_info.current_initial_secret->client_initial_secret.iv), IV_SIZE);
        len_count += IV_SIZE;
        memcpy(secret + len_count, &(quic_info.current_initial_secret->client_initial_secret.hp), HP_SIZE);
        len_count += HP_SIZE;

        // server Initial secret
        memcpy(secret + len_count, &(quic_info.current_initial_secret->server_initial_secret.secret), SECRET_SIZE);
        len_count += SECRET_SIZE;
        memcpy(secret + len_count, &(quic_info.current_initial_secret->server_initial_secret.key), KEY_SIZE);
        len_count += KEY_SIZE;
        memcpy(secret + len_count, &(quic_info.current_initial_secret->server_initial_secret.iv), IV_SIZE);
        len_count += IV_SIZE;
        memcpy(secret + len_count, &(quic_info.current_initial_secret->server_initial_secret.hp), HP_SIZE);
        len_count += HP_SIZE;
        
        
        if(quic_info.is_derived_handshake_traffic_secret){
            // add Handshake, 1-RTT secrets
            secret_size = secret_size + (SECRET_SIZE + KEY_SIZE + IV_SIZE + HP_SIZE)*4;
            secret = (u8 *)ck_realloc(secret, secret_size);

            // client Handshake secret
            memcpy(secret + len_count, &(quic_info.client_handshake_secret.secret), SECRET_SIZE);
            len_count += SECRET_SIZE;
            memcpy(secret + len_count, &(quic_info.client_handshake_secret.key), KEY_SIZE);
            len_count += KEY_SIZE;
            memcpy(secret + len_count, &(quic_info.client_handshake_secret.iv), IV_SIZE);
            len_count += IV_SIZE;
            memcpy(secret + len_count, &(quic_info.client_handshake_secret.hp), HP_SIZE);
            len_count += HP_SIZE;

            // server Handshake secret
            memcpy(secret + len_count, &(quic_info.server_handshake_secret.secret), SECRET_SIZE);
            len_count += SECRET_SIZE;
            memcpy(secret + len_count, &(quic_info.server_handshake_secret.key), KEY_SIZE);
            len_count += KEY_SIZE;
            memcpy(secret + len_count, &(quic_info.server_handshake_secret.iv), IV_SIZE);
            len_count += IV_SIZE;
            memcpy(secret + len_count, &(quic_info.server_handshake_secret.hp), HP_SIZE);
            len_count += HP_SIZE;

            // client Traffic secret
            memcpy(secret + len_count, &(quic_info.client_traffic_secret.secret), SECRET_SIZE);
            len_count += SECRET_SIZE;
            memcpy(secret + len_count, &(quic_info.client_traffic_secret.key), KEY_SIZE);
            len_count += KEY_SIZE;
            memcpy(secret + len_count, &(quic_info.client_traffic_secret.iv), IV_SIZE);
            len_count += IV_SIZE;
            memcpy(secret + len_count, &(quic_info.client_traffic_secret.hp), HP_SIZE);
            len_count += HP_SIZE;

            // server Traffic secret
            memcpy(secret + len_count, &(quic_info.server_traffic_secret.secret), SECRET_SIZE);
            len_count += SECRET_SIZE;
            memcpy(secret + len_count, &(quic_info.server_traffic_secret.key), KEY_SIZE);
            len_count += KEY_SIZE;
            memcpy(secret + len_count, &(quic_info.server_traffic_secret.iv), IV_SIZE);
            len_count += IV_SIZE;
            memcpy(secret + len_count, &(quic_info.server_traffic_secret.hp), HP_SIZE);
            len_count += HP_SIZE;
        }

        ck_write(fd, secret, len_count, filename);
    }

    close(fd);

    //Free the temporary buffer
    ck_free(secret);
}

// read all secret from a file
// so that afl-replay can re-encrypt the crashing inputs
void read_secrets_from_file(u8 *filename){
    struct stat st;
    s32 fd = open(filename, O_RDONLY);
    unsigned int max_file_size = (SECRET_SIZE + KEY_SIZE + IV_SIZE + HP_SIZE)*6;

    if (fd < 0) PFATAL("Unable to open '%s'", filename);

    // get file stats
    if (fstat(fd, &st) || !st.st_size) FATAL("Zero-sized secret file.");

    if (st.st_size > max_file_size) FATAL("Secret file is too large (%u bytes max)", max_file_size);

    unsigned char *secret = ck_alloc_nozero(st.st_size);
    // read the input from file and store in secret
    ck_read(fd, secret, st.st_size, filename);
    close(fd);

    

    if(quic_info.initial_secret == NULL && st.st_size > max_file_size/3){
        // extract initial secrets
        unsigned int len_count = 0;
        quic_info.initial_secret = (struct initial_secret *)ck_alloc(sizeof(struct initial_secret));

        // get client Initial secret
        memcpy(quic_info.initial_secret[quic_info.initial_secret_count].client_initial_secret.secret, secret, SECRET_SIZE);
        len_count += SECRET_SIZE;
        memcpy(quic_info.initial_secret[quic_info.initial_secret_count].client_initial_secret.key, secret+len_count, KEY_SIZE);
        len_count += KEY_SIZE;
        memcpy(quic_info.initial_secret[quic_info.initial_secret_count].client_initial_secret.iv, secret+len_count, IV_SIZE);
        len_count += IV_SIZE;
        memcpy(quic_info.initial_secret[quic_info.initial_secret_count].client_initial_secret.hp, secret+len_count, HP_SIZE);
        len_count += HP_SIZE;

        // get server Initial secret
        memcpy(quic_info.initial_secret[quic_info.initial_secret_count].server_initial_secret.secret, secret+len_count, SECRET_SIZE);
        len_count += SECRET_SIZE;
        memcpy(quic_info.initial_secret[quic_info.initial_secret_count].server_initial_secret.key, secret+len_count, KEY_SIZE);
        len_count += KEY_SIZE;
        memcpy(quic_info.initial_secret[quic_info.initial_secret_count].server_initial_secret.iv, secret+len_count, IV_SIZE);
        len_count += IV_SIZE;
        memcpy(quic_info.initial_secret[quic_info.initial_secret_count].server_initial_secret.hp, secret+len_count, HP_SIZE);
        len_count += HP_SIZE;

        quic_info.current_initial_secret = &quic_info.initial_secret[quic_info.initial_secret_count];
        quic_info.initial_secret_count++;

        // if there is Handshake and Traffic secrets, extract them as well.
        if(st.st_size ==  max_file_size){
            // get client Handshake secret
            memcpy(quic_info.client_handshake_secret.secret, secret+len_count, SECRET_SIZE);
            len_count += SECRET_SIZE;
            memcpy(quic_info.client_handshake_secret.key, secret+len_count, KEY_SIZE);
            len_count += KEY_SIZE;
            memcpy(quic_info.client_handshake_secret.iv, secret+len_count, IV_SIZE);
            len_count += IV_SIZE;
            memcpy(quic_info.client_handshake_secret.hp, secret+len_count, HP_SIZE);
            len_count += HP_SIZE;

            // get server Handshake secret
            memcpy(quic_info.server_handshake_secret.secret, secret+len_count, SECRET_SIZE);
            len_count += SECRET_SIZE;
            memcpy(quic_info.server_handshake_secret.key, secret+len_count, KEY_SIZE);
            len_count += KEY_SIZE;
            memcpy(quic_info.server_handshake_secret.iv, secret+len_count, IV_SIZE);
            len_count += IV_SIZE;
            memcpy(quic_info.server_handshake_secret.hp, secret+len_count, HP_SIZE);
            len_count += HP_SIZE;

            // get client Traffic secret
            memcpy(quic_info.client_traffic_secret.secret, secret+len_count, SECRET_SIZE);
            len_count += SECRET_SIZE;
            memcpy(quic_info.client_traffic_secret.key, secret+len_count, KEY_SIZE);
            len_count += KEY_SIZE;
            memcpy(quic_info.client_traffic_secret.iv, secret+len_count, IV_SIZE);
            len_count += IV_SIZE;
            memcpy(quic_info.client_traffic_secret.hp, secret+len_count, HP_SIZE);
            len_count += HP_SIZE;

            // get server Traffic secret
            memcpy(quic_info.server_traffic_secret.secret, secret+len_count, SECRET_SIZE);
            len_count += SECRET_SIZE;
            memcpy(quic_info.server_traffic_secret.key, secret+len_count, KEY_SIZE);
            len_count += KEY_SIZE;
            memcpy(quic_info.server_traffic_secret.iv, secret+len_count, IV_SIZE);
            len_count += IV_SIZE;
            memcpy(quic_info.server_traffic_secret.hp, secret+len_count, HP_SIZE);
            len_count += HP_SIZE;

        }else{
            WARNF("The Handshake and Traffic secrets are missing.");
        }
    }else{
        WARNF("The secret file is not completed.");
    }
    
    if(secret) ck_free(secret);
}

// Appendix A.3, RFC 9000
// decode the truncated packet number to candidate packet number (full packet num)
// use during decryption
// return candidate packet number, 0 means fail
uint64_t decode_packet_number(int is_client, enum PacketType packet_type, uint32_t truncated_packet_num, unsigned int packet_num_bits){
    uint64_t *expected_packet_num;

    // rfc example:
    // uint64_t expected_packet_num = 0xa82f30ea + 1;
    // truncated_packet_num = 0x9b32;
    // packet_num_bits = 16;

    // get the expected packet number
    if(is_client){
        switch (packet_type){
        case Initial:
            expected_packet_num = &quic_info.client_expected_initial_num;
            break;
        case Handshake:
            expected_packet_num = &quic_info.client_expected_handshake_num;
            break;
        case ZeroRTT:
        case OneRTT:
            expected_packet_num = &quic_info.client_expected_traffic_num;
            break;
        default:
            return 0;
        }
    }else{
        switch (packet_type){
        case Initial:
            expected_packet_num = &quic_info.server_expected_initial_num;
            break;
        case Handshake:
            expected_packet_num = &quic_info.server_expected_handshake_num;
            break;
        case ZeroRTT:
        case OneRTT:
            expected_packet_num = &quic_info.server_expected_traffic_num;
            break;
        default:
            return 0;
        }
    }
    
    uint64_t packet_num_win = UINT64_C(1) << packet_num_bits;
    uint64_t packet_num_hwin = packet_num_win / 2;
    uint64_t packet_num_mask = packet_num_win - 1;
    
    // packet number can be a 62 bits (0 - 2^61) number
    uint64_t candidate_packet_num = (*expected_packet_num & ~packet_num_mask) | truncated_packet_num;

    // if expected_packet_num is less than packet_num_hwin, skip so that -tive value will not become +tive
    if(*expected_packet_num > packet_num_hwin){
        if(candidate_packet_num <= *expected_packet_num - packet_num_hwin && candidate_packet_num < (UINT64_C(1) << 62) - packet_num_win){
        candidate_packet_num += packet_num_win;
        *expected_packet_num = candidate_packet_num + 1;
        return candidate_packet_num;
        }
    }

    if(candidate_packet_num > *expected_packet_num + packet_num_hwin && candidate_packet_num >= packet_num_win){
        candidate_packet_num -= packet_num_win;
        *expected_packet_num = candidate_packet_num + 1;
        return candidate_packet_num;
    }

    *expected_packet_num = candidate_packet_num + 1;
    
    return candidate_packet_num;
}

// compute the header protection mask
// this is used to apply and remove header protection
// return the len of the mask, 0 means fail
unsigned int get_header_protection_mask(int is_client, enum PacketType packet_type, unsigned char *sample, unsigned char *mask){
    unsigned int len;
    unsigned char *hp;

    // get the header protection secret
    if(is_client){
        switch (packet_type){
        case Initial:
            hp = quic_info.current_initial_secret->client_initial_secret.hp;
            break;
        case Handshake:
            hp = quic_info.client_handshake_secret.hp;
            break;
        case ZeroRTT:
        case OneRTT:
            hp = quic_info.client_traffic_secret.hp;
            break;
        default:
            return 0;
        }
    }else{
        switch (packet_type){
        case Initial:
            hp = quic_info.current_initial_secret->server_initial_secret.hp;
            break;
        case Handshake:
            hp = quic_info.server_handshake_secret.hp;
            break;
        case ZeroRTT:
        case OneRTT:
            hp = quic_info.server_traffic_secret.hp;
            break;
        default:
            return 0;
        }
    }

    EVP_CIPHER_CTX *ctx;

    // create a cipher context.
    if(!(ctx = EVP_CIPHER_CTX_new())){
        WARNF("Not able to create a cipher context.");
        return 0;
    }

    /* Initialise the encryption operation. */
    if(!EVP_CipherInit_ex(ctx, EVP_aes_128_ecb(), NULL, NULL, NULL, 1)){
        WARNF("Not able to initialise a AES_128_ECB context.");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    /* Set hp length. */
    if(!EVP_CIPHER_CTX_set_key_length(ctx, HP_SIZE)){
        WARNF("Not able to set hp length.");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    /* Initialise the encryption operation. */
    if(!EVP_CipherInit_ex(ctx, NULL, NULL, hp, NULL, 1)){
        WARNF("Not able to initialise a hp_key.");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    /* Encrypt. */
    if(!EVP_CipherUpdate(ctx, mask, &len, sample, SAMPLE_SIZE)){
        WARNF("Not able to decrypt and get the mask.");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    // clean up
    EVP_CIPHER_CTX_free(ctx);

    // return the length of the mask, 0 means error.
    return len;
}

// Section 5.4, RFC 9001
// get the packet number length from the packet before encryption
// get the mask, mask first byte and the packet number field 
// return 1 if success, 0 if fail
unsigned int apply_header_protection(int is_client, unsigned char *packet, enum PacketType packet_type, unsigned int packet_num_offset){
    // example:
    // c3 00 00 00 01 08 f3 86 02 ac b9 a6 e0 9a 08 2f 54 28 39 60 ac 14 71 00 44 e6 00 00 00 00 
    // need to ecode to 
    // cd 00 00 00 01 08 f3 86 02 ac b9 a6 e0 9a 08 2f 54 28 39 60 ac 14 71 00 44 e6 11 07 67 52

    unsigned char sample[SAMPLE_SIZE];
    unsigned int sample_offset = packet_num_offset + MAX_TRUNCATED_PACKET_NUM_SIZE;
    unsigned char mask[KEY_SIZE];
    unsigned int ret;
    unsigned int packet_num_len = (packet[0] & 0x03) + 1;

    // get sample (16 bytes)
    memcpy(sample, packet + sample_offset, SAMPLE_SIZE);
    memset(mask, 0, KEY_SIZE);

    ret = get_header_protection_mask(is_client, packet_type, sample, mask);
    
    if(ret == 0){
        return 0;
    }

    if(packet_type == OneRTT){
        // Short header: 5 bits masked
        packet[0] ^= mask[0] & 0x1f;
    }else{
        // Long header: 4 bits masked
        packet[0] ^= mask[0]& 0x0f;
    }
    
    // apply mask here
    // pn_offset is the start of the Packet Number field.
    for(int i=0; i<packet_num_len; i++){
        packet[packet_num_offset+i] ^= mask[1+i];
    }

    return 1;
}

// Section 5.4, RFC 9001
// remove header protection and get the truncated packet number
// return truncated packet number length 
unsigned int remove_header_protection(int is_client, unsigned char *packet, enum PacketType packet_type, unsigned int packet_num_offset, uint32_t *truncated_packet_num){
    unsigned char sample[SAMPLE_SIZE];
    unsigned int sample_offset = packet_num_offset + MAX_TRUNCATED_PACKET_NUM_SIZE;
    unsigned char mask[KEY_SIZE];
    unsigned int ret;
    unsigned int truncated_packet_num_len;

    // get sample (16 bytes)
    memcpy(sample, packet + sample_offset, SAMPLE_SIZE);
    memset(mask, 0, KEY_SIZE);

    /* RFC 9001 example*/
    // header[0] = 0xc0;
    // header[packet_num_offset] = 0x7b;
    // header[packet_num_offset + 1] = 0x9a;
    // header[packet_num_offset + 2] = 0xec;
    // header[packet_num_offset + 3] = 0x34;
    // unsigned char rfc_sample[]={0xd1, 0xb1, 0xc9, 0x8d, 0xd7, 0x68, 0x9f, 0xb8, 0xec, 0x11, 0xd2, 0x42, 0xb1, 0x23, 0xdc, 0x9b};

    ret = get_header_protection_mask(is_client, packet_type, sample, mask);

    if(ret == 0){
        return 0;
    }
    
    if(packet_type == OneRTT){
        // Short header: 5 bits masked
        packet[0] ^= mask[0] & 0x1f;
    }else{
        // Long header: 4 bits masked
        packet[0] ^= mask[0]& 0x0f;
    }

    truncated_packet_num_len = (packet[0] & 0x03) + 1;

    if(truncated_packet_num_len > 4){
        WARNF("Packet number length is more than 4.\n");
        return 0;
    }

    for(int i=0; i<truncated_packet_num_len; i++){
        packet[packet_num_offset + i] ^= mask[1+i];

        if(i != 0){
            *truncated_packet_num = (*truncated_packet_num << 8) + packet[packet_num_offset + i];
        }else{
            *truncated_packet_num = packet[packet_num_offset + i];
        }
    }

    return truncated_packet_num_len;
}

// Section 5.3, RFC 9001
// get nonce encryption and decryption
// return the address of nonce
unsigned char *get_nonce(int is_client, uint64_t candidate_packet_num, enum PacketType packet_type){
    unsigned char *nonce;
    unsigned char *iv;
    nonce = (char *)ck_alloc(IV_SIZE);

    if(is_client){
        switch (packet_type){
        case Initial:
            iv = quic_info.current_initial_secret->client_initial_secret.iv;
            break;
        case Handshake:
            iv = quic_info.client_handshake_secret.iv;
            break;
        case ZeroRTT:
        case OneRTT:
            iv = quic_info.client_traffic_secret.iv;
            break;
        default:
            return NULL;
        }
    }else{
        switch (packet_type){
        case Initial:
            iv = quic_info.current_initial_secret->server_initial_secret.iv;
            break;
        case Handshake:
            iv = quic_info.server_handshake_secret.iv;
            break;
        case ZeroRTT:
        case OneRTT:
            iv = quic_info.server_traffic_secret.iv;
            break;
        default:
            return NULL;
        }
    }

    memcpy(nonce, iv, IV_SIZE);
    
    // perform xor on the iv and candidate packet number
    for(int i=0; i<CANDIDATE_PACKET_NUM_SIZE; i++){
        nonce[i+(IV_SIZE-CANDIDATE_PACKET_NUM_SIZE)] ^= (candidate_packet_num << 8*i) >> 8*(CANDIDATE_PACKET_NUM_SIZE-1);
    }

    return nonce;
}

// get the secret for encryption and decryption
// the server should not send 0-RTT packet, therefore, do not need to get 0-RTT secret.
// return the address of the secret
struct endpoint_secret *get_end_point_secret(int is_client, enum PacketType packet_type){
    struct endpoint_secret *secret;

    if(is_client){
        switch (packet_type){
        case Initial:
            secret = &quic_info.current_initial_secret->client_initial_secret;
            break;
        case Handshake:
            secret = &quic_info.client_handshake_secret;
            break;
        case ZeroRTT:
        case OneRTT:
            secret = &quic_info.client_traffic_secret;
            break;
        default:
            return NULL;
        }
    }else{
        switch (packet_type){
        case Initial:
            secret = &quic_info.current_initial_secret->server_initial_secret;
            break;
        case Handshake:
            secret = &quic_info.server_handshake_secret;
            break;
        case ZeroRTT:
        case OneRTT:
            secret = &quic_info.server_traffic_secret;
            break;
        default:
            return NULL;
        }   
    }

    return secret;
}

// get the full packet number (62 bits value) from the unecrypted packet based on the truncated packet number
// return candidate packet number 
uint64_t get_candidate_packet_num(unsigned char *packet, unsigned int packet_num_offset){
    unsigned packet_num_len = (packet[0] & 0x3) + 1;
    uint64_t candidate_packet_num = 0;

    while(packet_num_len > 0){
        candidate_packet_num = (candidate_packet_num << 8) + packet[packet_num_offset];
        packet_num_offset++;
        packet_num_len--; 
    }
    
    return candidate_packet_num;
}

// get associate data = start from the packet until the end of packet number field
// return associate data length
unsigned int get_associate_data(unsigned char *packet, unsigned int packet_num_offset, unsigned char **associate_data){
    unsigned int packet_num_len = (packet[0] & 0x3) + 1;    
    unsigned int associate_data_len = packet_num_offset + packet_num_len;

    *associate_data = (char *)ck_alloc(associate_data_len);
    memcpy(*associate_data, packet, associate_data_len);

    return associate_data_len;
}

// get the payload (from the end of packet number until the end of the packet)
// return payload length
unsigned int get_payload(unsigned char *packet, unsigned int packet_len, unsigned int packet_num_offset, unsigned char **payload){
    unsigned int packet_num_len = (packet[0] & 0x3) + 1;
    unsigned int payload_len = packet_len - (packet_num_offset + packet_num_len);

    *payload = (char *)ck_alloc(payload_len);
    memcpy(*payload, packet+packet_num_offset+packet_num_len, payload_len);
    
    return payload_len;
}

// get the correct current_initial_secret before Initial packet encryption
// return 1 if the correct initial secret is found, else return 0;
unsigned int get_correct_current_initial_secret(unsigned char *packet, unsigned int packet_len){
    // loop until scid
    unsigned int version_offset = 1; // after first byte
    unsigned int dcid_len_offset = version_offset + 4; // after version bytes
    unsigned int dcid_offset = dcid_len_offset + 1; // after the dcid len byte
    unsigned int scid_len_offset = dcid_offset + *(packet+dcid_len_offset); // after the dcid bytes

    if(packet_len <= scid_len_offset){
        return 0;
    }

    unsigned int dcid_len = *(packet+dcid_len_offset);
    unsigned int scid_len = *(packet+scid_len_offset);
    unsigned int scid_offset = scid_len_offset + 1; // after the dcid len byte

    // In retry mode, if this Initial packet has same dcid as the first encrypted Initial packet in the seed,
    // return 0 because we no need to encrypt it.
    if(is_retry && quic_info.pre_init_dcid.cid_len == dcid_len){
        if(memcmp(packet+dcid_offset, quic_info.pre_init_dcid.cid, dcid_len) == 0){
            return 0;
        }
    }

    if(packet_len <= scid_offset + scid_len){
        return 0;
    }

    // match the scid with the source connection id of the current_initial_secret
    if(quic_info.current_initial_secret->client_source_conn_id_len == scid_len){
        if(memcmp(packet+scid_offset, quic_info.current_initial_secret->client_source_conn_id, scid_len) == 0){
            // print_byte_string_to_log("testing", "Same: ", NULL, packet+scid_offset, scid_len);
            return 1;
        }
    }
    
    // if it does not match the current_initial_secret, find the correct initial secret for this packet
    for(int i=0; i<quic_info.initial_secret_count; i++){
        if(scid_len == quic_info.initial_secret[i].client_source_conn_id_len){
            if(memcmp(packet+scid_offset, quic_info.initial_secret[i].client_source_conn_id, scid_len) == 0){
                quic_info.current_initial_secret = &quic_info.initial_secret[i];
                //  print_byte_string_to_log("testing", "Changed: ", NULL, packet+scid_offset, scid_len);
                return 1;
            }
        }
    }

    return 0;
}

// encrypte packet
// return encrypted packet length, 0 means encryption fails
unsigned int encrypt_payload(int is_client, enum PacketType packet_type, uint64_t candidate_packet_num, unsigned char *associate_data, unsigned int associate_data_len, unsigned char *payload, unsigned int payload_len, unsigned int packet_num_offset, unsigned char *encrypted_payload, unsigned char *auth_tag){
    EVP_CIPHER_CTX *ctx;
    int ret;
    unsigned int encrypted_payload_len = 0, out_len;
    struct endpoint_secret *secret = get_end_point_secret(is_client, packet_type);
    unsigned char *nonce = get_nonce(is_client, candidate_packet_num, packet_type);

    if(secret == NULL || nonce == NULL){
        return 0;
    }

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())){
        printf("Not able to create a cipher context.");
        return 0;
    }

    /* Initialise the encryption operation. */
    if(!EVP_CipherInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL, 1)){
        printf("Not able to initialise a AES_128_GCM context.");
        EVP_CIPHER_CTX_free(ctx);
        if(nonce) ck_free(nonce);
        return 0;
    }

    /* Set key length. */
    if(!EVP_CIPHER_CTX_set_key_length(ctx, KEY_SIZE)){
        printf("Not able to set key size.");
        EVP_CIPHER_CTX_free(ctx);
        if(nonce) ck_free(nonce);
        return 0;
    }

    /* Set IV length. */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE, NULL)){
        printf("Not able to set iv length.");
        EVP_CIPHER_CTX_free(ctx);
        if(nonce) ck_free(nonce);
        return 0;
    }

    /* Initialise key and IV */
    if(!EVP_CipherInit_ex(ctx, NULL, NULL, secret->key, nonce, 1)){
        printf("Not able to initialise a key and iv.");
        EVP_CIPHER_CTX_free(ctx);
        if(nonce) ck_free(nonce);
        return 0;
    }

    // // Provide any AAD data. This can be called zero or more times as required
    if(!EVP_CipherUpdate(ctx, NULL, &encrypted_payload_len, associate_data, associate_data_len)){
        printf("Not able to provide the nonce.");
        EVP_CIPHER_CTX_free(ctx);
        if(nonce) ck_free(nonce);
        return 0;
    }

    // Provide the message to be decrypted, and obtain the plaintext output.
    if(!EVP_CipherUpdate(ctx, encrypted_payload, &encrypted_payload_len, payload, payload_len)){
        printf("Not able to provide payload.");
        EVP_CIPHER_CTX_free(ctx);
        if(nonce) ck_free(nonce);
        return 0;
    }

    // Finalise the decryption. A positive return value indicates success, anything else is a failure - the plaintext is not trustworthy.
    if(!EVP_CipherFinal_ex(ctx, NULL, &out_len)){
        EVP_CIPHER_CTX_free(ctx);
        if(nonce) ck_free(nonce);
        return 0;
    }

    /* Get the auth tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AUTH_TAG_SIZE, auth_tag)){
        printf("Not able to get the authentication tag.");
        EVP_CIPHER_CTX_free(ctx);
        if(nonce) ck_free(nonce);
        return 0;
    }

    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    if(nonce) ck_free(nonce);

    return encrypted_payload_len;
}

// decrypt packet
// return decrypted packet length, 0 means decryption fails
unsigned int decrypt_payload(int is_client, enum PacketType packet_type, uint64_t candidate_packet_num, unsigned char *associate_data, unsigned int associate_data_len, unsigned char *payload, unsigned int payload_len, unsigned char *decrypted_payload){
    EVP_CIPHER_CTX *ctx;
    int ret;
    int decrypted_payload_len = 0, out_len;
    struct endpoint_secret *secret = get_end_point_secret(is_client, packet_type);
    unsigned char *nonce = get_nonce(is_client, candidate_packet_num, packet_type);

    if(secret == NULL || nonce == NULL){
        return 0;
    }

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())){
        printf("Not able to create a cipher context.");
        return 0;
    }

    /* Initialise the decryption operation. */
    if(!EVP_CipherInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL, 0)){
        printf("Not able to initialise a AES_128_GCM context.");
        EVP_CIPHER_CTX_free(ctx);
        if(nonce) ck_free(nonce);
        return 0;
    }

    /* Set key length. */
    if(!EVP_CIPHER_CTX_set_key_length(ctx, KEY_SIZE)){
        printf("Not able to set key size.");
        EVP_CIPHER_CTX_free(ctx);
        if(nonce) ck_free(nonce);
        return 0;
    }

    /* Set IV length. */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE, NULL)){
        printf("Not able to set iv length.");
        EVP_CIPHER_CTX_free(ctx);
        if(nonce) ck_free(nonce);
        return 0;
    }

    /* Set expected authentication tag value. Works in OpenSSL 1.0.1d and later */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AUTH_TAG_SIZE, (void*)(payload+(payload_len - AUTH_TAG_SIZE)))){
        printf("Not able to set authentication tag.");
        EVP_CIPHER_CTX_free(ctx);
        if(nonce) ck_free(nonce);
        return 0;
    }
    
    /* Initialise key and IV */
    if(!EVP_CipherInit_ex(ctx, NULL, NULL, secret->key, nonce, 0)){
        printf("Not able to initialise a key and iv.");
        EVP_CIPHER_CTX_free(ctx);
        if(nonce) ck_free(nonce);
        return 0;
    }

    // // Provide any AAD data. This can be called zero or more times as required
    if(!EVP_CipherUpdate(ctx, NULL, &decrypted_payload_len, associate_data, associate_data_len)){
        printf("Not able to provide the nonce.");
        EVP_CIPHER_CTX_free(ctx);
        if(nonce) ck_free(nonce);
        return 0;
    }

    // Provide the message to be decrypted, and obtain the plaintext output.
    if(!EVP_CipherUpdate(ctx, decrypted_payload, &decrypted_payload_len, payload, payload_len - AUTH_TAG_SIZE)){
        printf("Not able to provide payload.");
        EVP_CIPHER_CTX_free(ctx);
        if(nonce) ck_free(nonce);
        return 0;
    }

    // Finalise the decryption. A positive return value indicates success, anything else is a failure - the plaintext is not trustworthy.
    if(!EVP_CipherFinal_ex(ctx, NULL, &out_len)){
        EVP_CIPHER_CTX_free(ctx);
        if(nonce) ck_free(nonce);
        return 0;
    }

    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    if(nonce) ck_free(nonce);

    return decrypted_payload_len;
}

// given a byte stream, the beginning part of the packet
// identify the type of the packet
// return the packet type, return Error (5) if fail
enum PacketType get_packet_type(unsigned char *byte_strean, unsigned int byte_stream_len){
    // make there is at least 1 bytes 
    if(byte_stream_len < 1){
        return Error;
    }

    // if the first bit of the first byte is 0 then it is one-rtt packet.
    if(!(byte_strean[0] & (1 << 7))){
        return OneRTT;
    }else{
        // when the position 5 and 4 (6th and 5th bits from the right) is not set, Initial packet
        if(!(byte_strean[0] & (1 << 5)) && !(byte_strean[0] & (1 << 4))){ 
            // Initial packet
            return Initial;

        // when the position 5 (6th bit from the right) is not set but the position 4 (5th bit from the right) is set, 0-RTT packet
        }else if(!(byte_strean[0] & (1 << 5)) && (byte_strean[0] & (1 << 4))){
            // 0-RTT packet
            return ZeroRTT;

        // when the position 5 (6th bit from the right) is set but the position 4 (5th bit from the right) is not set, Handshake packet
        }else if((byte_strean[0] & (1 << 5)) && !(byte_strean[0] & (1 << 4))){ 
            // Handshake packet
            return Handshake;

        // when the position 5 and 4 (6th and 5th bits from the right) is set, Retry packet
        }else if((byte_strean[0] & (1 << 5)) && (byte_strean[0] & (1 << 4))){ 
            // Retry packet
            return Retry;
        }else{
            return Error;
        }
    }
}

// return the packet number offset, return 0 if fail/error
unsigned int get_long_head_pkt_num_offset(char *byte_stream, unsigned int byte_stream_len, enum PacketType packet_type){
    // there is no packet number in Version Negotiation and Retry packets
    if(packet_type == Retry || packet_type == Error){
        return 0;
    }
    
    // need to have at least 7 bytes (minimum length according to Section 17.2, RFC 9000)
    if(byte_stream_len < 7){
        return 0;
    }

    // make sure it is long header packet
    if(!is_long_head_pkt(byte_stream, byte_stream_len)){
        return 0;
    }

    // add up DCID lenght field and DCID field
    unsigned int byte_count = 5; // start from DCID length field
    byte_count += byte_stream[5]; // plus DCID field
    byte_count++; // plus SCID length field

    if(byte_stream_len < byte_count){
            return 0;
    }

    byte_count += byte_stream[byte_count]; // plus SCID field

    // special for Initial (token length + token)
    if(packet_type == Initial){
        byte_count++; // plus token length field
        
        if(byte_stream_len < byte_count){
            return 0;
        }

        byte_count += byte_stream[byte_count]; // plus token field
    }

    // length of the packet length field
    byte_count++;

    if(byte_stream_len < byte_count){
            return 0;
    }

    unsigned int prefix = byte_stream[byte_count] >> 6;
    unsigned int length = (1 << prefix) -1; // this include the first byte we have counted
    byte_count += length; 
    byte_count++; // move to the packet number field

    // if the byte_count > byte_stream_len && default < byte_stream_len
    // return default (but need check if the)
    return byte_count;
}

// given a byte stream (begining of the 1-rtt packet)
// only used in extract_response_quic()
// return the correct packet number offset of 1-RTT packet
unsigned int get_one_rtt_pkt_num_offset(unsigned int is_send, unsigned char *byte_stream, unsigned int byte_stream_len){
    unsigned int offset = 0; 

    // if this is a sending packet, we check with the client DCID
    if(is_send){
        // identify the DCID in the client DCIDs list to know the DCID length
        for(int i=0; i<quic_info.one_rtt_dcid_count; i++){
            if(byte_stream_len - 1 >= quic_info.one_rtt_dcid[i].cid_len){
                if(memcmp(byte_stream + 1, quic_info.one_rtt_dcid[i].cid, quic_info.one_rtt_dcid[i].cid_len) == 0){
                    offset = 1 + quic_info.one_rtt_dcid[i].cid_len;
                    return offset;
                }
            }
        }
    }else{
        // identify the DCID according to the client SCIDs list to know the DCID length
        for(int i=0; i<quic_info.initial_secret_count; i++){
            if(byte_stream_len - 1 >= quic_info.initial_secret[i].client_source_conn_id_len){
                if(memcmp(byte_stream + 1, quic_info.initial_secret[i].client_source_conn_id, quic_info.initial_secret[i].client_source_conn_id_len) == 0){
                    offset = 1 + quic_info.initial_secret[i].client_source_conn_id_len; // first bit + the DCID length
                    return offset;
                }
            }
        }
    }

    if(offset == 0 && byte_stream_len >= (1 + CONN_ID_MAX_SIZE)){
        // if hit the max offset, set it to the one use by most implementations (1 + 8 DCID length)
        return 1 + 8; 
    }

    return offset;
}

// given a byte stream (part of the packet), check whether this is a version negotiation packet.
// version negotiation packet has 1st bit = 0b1 and 2nd-5th byte = 0x00.
// if the given byte stream is too short (< CHECK_VERSION_NEGO_PKT_LEN), exit.
// return 1 (yes), 0 (no)
unsigned int is_version_nego_pkt(unsigned char *byte_stream, unsigned int byte_stream_len){    
    if(byte_stream_len < CHECK_VERSION_NEGO_PKT_LEN){
        fprintf(stderr, "ERROR: Please provide a byte stream > %d bytes to is_version_nego_pkt().", CHECK_VERSION_NEGO_PKT_LEN);
        exit(EXIT_FAILURE);
    }

    // check the bits and version
    if(byte_stream[0] & (1 << 7) && byte_stream[1] == 0 && byte_stream[2] == 0 && 
        byte_stream[3] == 0 && byte_stream[4] == 0){
        return 1;
    }
    
    return 0;
}

// given a byte stream (part of the packet), check whether this is a long header packet.
// long header packet has 1st bit = 0b1, 2nd bit = 0b1, 2nd-4th byte = 0x00 and 5th byte = 0x01.
// if the given byte stream is too short (< CHECK_LONG_HEAD_PKT_LEN), exit.
// return 1 (yes), 0 (no)
unsigned int is_long_head_pkt(unsigned char *byte_stream, unsigned int byte_stream_len){    
    if(byte_stream_len < CHECK_LONG_HEAD_PKT_LEN){
        fprintf(stderr, "ERROR: Please provide a byte stream > %d bytes to is_long_head_pkt().", CHECK_LONG_HEAD_PKT_LEN);
        exit(EXIT_FAILURE);
    }

    // check the first byte 
    if(byte_stream[0] & (1 << 7) && byte_stream[0] & (1 << 6)){

        // extract the version first time
        if(quic_info.quic_version == No_Assigned){
            if(memcmp(byte_stream + 1, version_1_value, sizeof(version_1_value)) == 0){
                quic_info.quic_version = Version_1;
                return 1;
            }
            
            if(memcmp(byte_stream + 1, draft_29_value, sizeof(draft_29_value)) == 0){
                quic_info.quic_version = Draft_29;
                return 1;
            }
        }else{
            // check version
            if(quic_info.quic_version == Version_1 && 
                    memcmp(byte_stream + 1, version_1_value, sizeof(version_1_value)) == 0){
                return 1;
            }

            if(quic_info.quic_version == Draft_29 && 
                    memcmp(byte_stream + 1, draft_29_value, sizeof(draft_29_value)) == 0){
                return 1;
            }
        }
    }

    return 0;
}

// given a byte stream (part of the packet), check whether this is a short header packet.
// short header packet has 1st bit = 0b0, 2nd bit = 0b1 and 2nd-Nth byte is the DCID.
// if the given byte stream is too short (< 1 + CONN_ID_MAX_SIZE), exit.
// return 1 (yes), 0 (no)
unsigned int is_short_head_pkt(unsigned char *byte_stream, unsigned int byte_stream_len, unsigned int is_recv){
    if(byte_stream_len < (1 + CONN_ID_MAX_SIZE)){
        PFATAL("ERROR: Please provide a byte stream > %d bytes to is_short_head_pkt().", 1+CONN_ID_MAX_SIZE);
    }
    
    // check the first 2 bits
    if(!(byte_stream[0] & (1 << 7)) && byte_stream[0] & (1 << 6)){
        if(is_recv && quic_info.one_rtt_scid != NULL && quic_info.one_rtt_scid_count > 0){
            // check if the DCID from the server's packet match the DCIDs in the list
            for(int i=0; i<quic_info.one_rtt_scid_count; i++){
                if(byte_stream_len - 1 >= quic_info.one_rtt_scid[i].cid_len){
                    if(memcmp(byte_stream + 1, quic_info.one_rtt_scid[i].cid, quic_info.one_rtt_scid[i].cid_len) == 0){
                        return 1;
                    }
                }
            }
        }else if(!is_recv && quic_info.one_rtt_dcid != NULL && quic_info.one_rtt_dcid_count > 0){
            // check if the DCID from the client packet match the server SCID 
            for(int i=0; i<quic_info.one_rtt_dcid_count; i++){
                if(byte_stream_len - 1 >= quic_info.one_rtt_dcid[i].cid_len){
                    if(memcmp(byte_stream + 1, quic_info.one_rtt_dcid[i].cid, quic_info.one_rtt_dcid[i].cid_len) == 0){
                        return 1;
                    }
                }
            }

            // or the DCID from the server packet match the client SCID (when generating training data for LLM)
            if(is_gen_train_data){
                for(int i=0; i<quic_info.one_rtt_scid_count; i++){
                    if(byte_stream_len - 1 >= quic_info.one_rtt_scid[i].cid_len){
                        if(memcmp(byte_stream + 1, quic_info.one_rtt_scid[i].cid, quic_info.one_rtt_scid[i].cid_len) == 0){
                            return 1;
                        }
                    }
                }
            }
        }
    }

    return 0;
}

// parse ACK frame
// Section 19.3, RFC 9000
// return the frame code
unsigned int parse_ack(unsigned int frames, unsigned char *decrypted_payload, unsigned int decrypted_payload_len, unsigned int *decrypted_payload_count){
    enum FrameType ack_type = decrypted_payload[*decrypted_payload_count];
    frames |= (1 << ack_type);

    const unsigned int ack_field = 4;
    unsigned int ack_field_count = 0;
    const unsigned int ack_range_field = 2;
    unsigned int ack_range = 0;
    unsigned int ack_range_count = 0;
    
    // skip largest ack, ack delay, get ack range and skip first ack range fields
    while(*decrypted_payload_count + 1 < decrypted_payload_len && ack_field_count < ack_field){
        (*decrypted_payload_count)++;

        if(ack_field_count == ack_range_field){
            ack_range = variable_len_int_decode(decrypted_payload, decrypted_payload_count, &decrypted_payload_len, NULL, NULL, NULL, NULL);
        }else{
            variable_len_int_decode(decrypted_payload, decrypted_payload_count, &decrypted_payload_len, NULL, NULL, NULL, NULL);
        }

        ack_field_count++;
    }
    
    // skip any ack range detected
    while(*decrypted_payload_count + 1 < decrypted_payload_len && ack_range_count < ack_range){
        const unsigned int ack_range_field = 2;
        unsigned int ack_range_field_count = 0;
        
        while(*decrypted_payload_count + 1 < decrypted_payload_len && ack_range_field_count < ack_range_field){
            (*decrypted_payload_count)++;
            variable_len_int_decode(decrypted_payload, decrypted_payload_count, &decrypted_payload_len, NULL, NULL, NULL, NULL);
            ack_range_field_count++;
        }

        ack_range_count++;
    }

    if(ack_type == AckEcn){
        unsigned int ecn_field = 3;
        unsigned int ecn_count = 0;

        // skip ecn count
        while(*decrypted_payload_count + 1 < decrypted_payload_len && ecn_count < ecn_field){
            (*decrypted_payload_count)++;
            variable_len_int_decode(decrypted_payload, decrypted_payload_count, &decrypted_payload_len, NULL, NULL, NULL, NULL);
            ecn_count++;
        }
    }

    return frames;
}

// parse CRYPTO frame
// Section 19.6, RFC 9000
// return the frame code
unsigned int parse_crypto(unsigned int frames, unsigned char *decrypted_payload, unsigned int decrypted_payload_len, unsigned int *decrypted_payload_count){
    frames |= (1 << Crypto);
    const unsigned int crypto_field = 2;
    unsigned int crypto_filed_count = 0;
    unsigned int byte_to_skip = 0;
    unsigned int byte_count = 0;

    // skip offset and get byte to skip
    while(*decrypted_payload_count + 1 < decrypted_payload_len && crypto_filed_count < crypto_field){
        (*decrypted_payload_count)++;
        byte_to_skip = variable_len_int_decode(decrypted_payload, decrypted_payload_count, &decrypted_payload_len, NULL, NULL, NULL, NULL);
        crypto_filed_count++;
    }

    // skipping the crypto content
    while(*decrypted_payload_count + 1 < decrypted_payload_len && byte_count < byte_to_skip){
        (*decrypted_payload_count)++;
        byte_count++;
    }
    
    return frames;
}

// parse NEW_TOKEN frame
// Section 19.7, RFC 9000
// return the frame code
unsigned int parse_new_token(unsigned int frames, unsigned char *decrypted_payload, unsigned int decrypted_payload_len, unsigned int *decrypted_payload_count){
    frames |= (1 << NewToken);
    unsigned int token_len = 0;
    unsigned int token_count = 0;

    // get token length
    if(*decrypted_payload_count + 1 < decrypted_payload_len){
        (*decrypted_payload_count)++;
        token_len = variable_len_int_decode(decrypted_payload, decrypted_payload_count, &decrypted_payload_len, NULL, NULL, NULL, NULL);
    }
    
    // skip the token
    while(*decrypted_payload_count + 1 < decrypted_payload_len && token_count < token_len){
        (*decrypted_payload_count)++;
        token_count++;
    }

    return frames;
}

// parse NEW_CONNECTION_ID frame
// Section 19.15, RFC 9000
// return the frame code
unsigned int parse_new_connection_id(unsigned int frames, unsigned char *decrypted_payload, unsigned int decrypted_payload_len, unsigned int *decrypted_payload_count){
    frames |= (1 << NewConnectionID);
    const unsigned int field_to_skip = 2;
    unsigned int field_to_skip_count = 0;
    const unsigned int len = 1;
    unsigned int conn_id_len = 0;
    unsigned int conn_id_count = 0;
    const unsigned int stateless_reset_token_len = 16;
    unsigned int stateless_reset_token_count = 0;

    // skip sequence number and retire prior to fields 
    while(*decrypted_payload_count + 1 < decrypted_payload_len && field_to_skip_count < field_to_skip){
        (*decrypted_payload_count)++;
        variable_len_int_decode(decrypted_payload, decrypted_payload_count, &decrypted_payload_len, NULL, NULL, NULL, NULL);
        field_to_skip_count++;
    }
    
    // get connection id length
    if(*decrypted_payload_count + 1 < decrypted_payload_len){
        (*decrypted_payload_count)++;
        conn_id_len = decrypted_payload[*decrypted_payload_count];
    }

    if(decrypted_payload_len > *decrypted_payload_count + 1 + conn_id_len){
        add_cid(&quic_info.one_rtt_dcid, &quic_info.one_rtt_dcid_count, decrypted_payload + *decrypted_payload_count + 1, conn_id_len);
    }

    // skip connection id
    while(*decrypted_payload_count + 1 < decrypted_payload_len && conn_id_count < conn_id_len){
        (*decrypted_payload_count)++;
        conn_id_count++;
    }

    // skip stateless reset token
    while(*decrypted_payload_count + 1 < decrypted_payload_len && stateless_reset_token_count < stateless_reset_token_len){
        (*decrypted_payload_count)++;
        stateless_reset_token_count++;
    }

    return frames;
}

// parse CONNECTION_CLOSE frame
// Section 19.19, RFC 9000
// return the frame code
unsigned int parse_connection_close(unsigned int frames, unsigned char *decrypted_payload, unsigned int decrypted_payload_len, unsigned int *decrypted_payload_count){
    enum FrameType connection_close_type = decrypted_payload[*decrypted_payload_count];
    frames |= (1 << connection_close_type);
    unsigned int field_to_skip = 0;
    unsigned int field_to_skip_count = 0;
    unsigned int reason_phrase_len = 0;
    unsigned int reason_phrase_count = 0;

    if(connection_close_type == ConnectionClose){
        field_to_skip = 2;
    }else{
        field_to_skip = 1;
    }

    // skip error code and frame type (if any) fields
    while(*decrypted_payload_count + 1 < decrypted_payload_len && field_to_skip_count < field_to_skip){
        (*decrypted_payload_count)++;
        variable_len_int_decode(decrypted_payload, decrypted_payload_count, &decrypted_payload_len, NULL, NULL, NULL, NULL);
        field_to_skip_count++;
    }

    // get reason phrase length
    if(*decrypted_payload_count + 1 < decrypted_payload_len){
        (*decrypted_payload_count)++;
        reason_phrase_len = variable_len_int_decode(decrypted_payload, decrypted_payload_count, &decrypted_payload_len, NULL, NULL, NULL, NULL);
    }

    // skip reason phrase
    while(*decrypted_payload_count + 1 < decrypted_payload_len && reason_phrase_count < reason_phrase_len){
        (*decrypted_payload_count)++;
        reason_phrase_count++;
    }

    return frames;
}

// decrypt the payload
// return the frame code (aka status code)
unsigned int get_frame_type(unsigned char *decrypted_payload, unsigned int decrypted_payload_len){
    // try to get PING, CRYPTO, CONNECTION_CLOSE
    unsigned int decrypted_payload_count = 0;
    unsigned int frames = 0;

    while(decrypted_payload_count < decrypted_payload_len){
        switch(decrypted_payload[decrypted_payload_count]){
        case Padding:
            frames  |= (1 << Padding);
            break;
        case Ping:
            frames |= (1 << Ping);
            break;
        case Ack:
        case AckEcn:
            frames = parse_ack(frames, decrypted_payload, decrypted_payload_len, &decrypted_payload_count);
            break;
        case Crypto:
            frames = parse_crypto(frames, decrypted_payload, decrypted_payload_len, &decrypted_payload_count);
            break;
        case NewToken:
            frames = parse_new_token(frames, decrypted_payload, decrypted_payload_len, &decrypted_payload_count);
            break;
        case NewConnectionID:
            frames = parse_new_connection_id(frames, decrypted_payload, decrypted_payload_len, &decrypted_payload_count);
            break;
        case ConnectionClose:
        case ConnectionCloseApplication:
            frames =  parse_connection_close(frames, decrypted_payload, decrypted_payload_len, &decrypted_payload_count);
            break;
        case HandshakeDone:
            frames |= (1 << HandshakeDone);
            break;
        default:
            break;
        }

        decrypted_payload_count++;
    }

    return frames;
}

// decrypt the entire packet including removing the header protection and decrypt the payload
// if the argument "frame" is NULL, do not parse the frame  after decryption (mostly used when decrypting the seed)
// return the decrypted packet length, 0 means decryption fails
unsigned int decrypt_packet(int is_client, unsigned char *packet, unsigned int packet_len, unsigned int packet_num_offset, enum PacketType packet_type, unsigned char **decrypted_packet, unsigned int *frame_type){
    unsigned int truncated_packet_num_len = 0;
    uint32_t truncated_packet_num;
    uint64_t candidate_packet_num;
    unsigned char *associate_data = NULL;
    unsigned int associate_data_len;
    unsigned char *payload = NULL;
    unsigned int payload_offset;
    unsigned int payload_len;
    unsigned char *decrypted_payload = NULL;
    unsigned int decrypted_payload_len = 0;
    
    // make sure the packet number field + sample field is >= 20
    if(packet_type == Initial || packet_type == Handshake || packet_type == OneRTT){
        if(packet_len - packet_num_offset < 20){
            return 0;
        }
    }

    // decrypt
    if(packet_type == Initial || packet_type == Handshake || packet_type == OneRTT){
        // remove header protection and get truncated packet number
        truncated_packet_num_len = remove_header_protection(is_client, packet, packet_type, packet_num_offset, &truncated_packet_num);
        
        // get candidate packet number
        candidate_packet_num = decode_packet_number(is_client, packet_type, truncated_packet_num, truncated_packet_num_len*8);

        if(truncated_packet_num_len == 0){
            return 0;
        }

        // get associate data
        associate_data_len = get_associate_data(packet, packet_num_offset, &associate_data);

        // get payload
        payload_len = get_payload(packet, packet_len, packet_num_offset, &payload);

        // decrypt the payload
        decrypted_payload=(char *)ck_alloc(payload_len);
        decrypted_payload_len = decrypt_payload(is_client, packet_type, candidate_packet_num, associate_data, associate_data_len, payload, payload_len, decrypted_payload);
    }

    // debug
    if(decrypted_payload_len == 0){
        // return 0 if fails to decrypt
        if(associate_data) ck_free(associate_data);
        if(payload) ck_free(payload);
        if(decrypted_payload) ck_free(decrypted_payload);
        return 0;
    }

    // from here the packet is fully decrypted in decrypted_packet
    unsigned int decrypted_packet_len = packet_num_offset+truncated_packet_num_len+decrypted_payload_len;
    *decrypted_packet=(char *)ck_alloc(decrypted_packet_len);
    memcpy(*decrypted_packet, packet, packet_num_offset+truncated_packet_num_len);
    memcpy(*decrypted_packet+packet_num_offset+truncated_packet_num_len, decrypted_payload, decrypted_payload_len);

    if(frame_type != NULL){
        *frame_type = get_frame_type(decrypted_payload, decrypted_payload_len);
    }
    
    if(associate_data) ck_free(associate_data);
    if(payload) ck_free(payload);
    if(decrypted_payload) ck_free(decrypted_payload);

    return decrypted_packet_len;
}


// encrypt packet
// return the encrypted packet length, 0 means encryption fails
unsigned int encrypt_packet(int is_client, unsigned char *packet, unsigned int packet_len, unsigned int packet_num_offset, enum PacketType packet_type, unsigned char **encrypted_packet){
    uint64_t candidate_packet_num;
    unsigned char *associate_data = NULL;
    unsigned int associate_data_len;
    unsigned char *payload = NULL;
    unsigned int payload_len;
    unsigned int truncated_packet_num_len = (packet[0] & 0x3) + 1;
    unsigned char *auth_tag = NULL;
    unsigned char *encrypted_payload = NULL;

    // make sure the packet number offset is more than 0
    // make sure the packet type is not error
    // make sure packet length is > packet number offset + truncated packet number + the sample for header protection
    if(packet_num_offset == 0 || packet_type == Error || packet_len < (packet_num_offset + truncated_packet_num_len)){
        return 0;
    }

    if(packet_type == Initial && !is_replay){
        // need to get the correct Initial secret before encryption
        if(get_correct_current_initial_secret(packet, packet_len) == 0){
            return 0;
        }
    }

    // because aflnet-replay will call this function directly, so we need to extract some information to encrypt the packet properly
    if(packet_type == Handshake && is_replay && quic_info.one_rtt_dcid_count == 0 && packet_len > 5){
        unsigned int dcid_len = packet[5];
        
        // extract the dcid from the Handshake packet to fill the 1rtt dcid and scid in quic_ info that will be used later
        if(packet_len > (5 + 1 + dcid_len)){
            unsigned int scid_len = packet[5 + dcid_len + 1];

            if(packet_len > (5 + 1 + dcid_len + 1 + scid_len)){
                add_cid(&quic_info.one_rtt_dcid, &quic_info.one_rtt_dcid_count, packet + 5 + 1, dcid_len);
                add_cid(&quic_info.one_rtt_scid, &quic_info.one_rtt_scid_count, packet + 5 + 1 + dcid_len + 1, scid_len);
            }
        }
    }

    candidate_packet_num = get_candidate_packet_num(packet, packet_num_offset);
    associate_data_len = get_associate_data(packet, packet_num_offset, &associate_data);
    payload_len = get_payload(packet, packet_len, packet_num_offset, &payload);

    encrypted_payload = (char *)ck_alloc(payload_len);
    auth_tag = (char *)ck_alloc(AUTH_TAG_SIZE);
    
    unsigned int encrypted_payload_len = encrypt_payload(is_client, packet_type, candidate_packet_num, associate_data, associate_data_len, payload, payload_len, packet_num_offset, encrypted_payload, auth_tag);
    
    if(encrypted_payload_len == 0){
        // return 0 if fails to encrypt
        if(associate_data) ck_free(associate_data);
        if(payload) ck_free(payload);
        if(auth_tag) ck_free(auth_tag);
        if(encrypted_payload) ck_free(encrypted_payload);
        return 0;
    }
    
    unsigned int encrypted_packet_len = packet_num_offset + truncated_packet_num_len + encrypted_payload_len + AUTH_TAG_SIZE;
    *encrypted_packet = (char *)ck_alloc(encrypted_packet_len);
    
    memcpy(*encrypted_packet, packet, packet_num_offset+truncated_packet_num_len);
    memcpy(*encrypted_packet+packet_num_offset+truncated_packet_num_len, encrypted_payload, encrypted_payload_len);
    memcpy(*encrypted_packet+packet_num_offset+truncated_packet_num_len+encrypted_payload_len, auth_tag, AUTH_TAG_SIZE);
    
    unsigned int ret = apply_header_protection(is_client, *encrypted_packet, packet_type, packet_num_offset);
    
    if(associate_data) ck_free(associate_data);
    if(payload) ck_free(payload);
    if(auth_tag) ck_free(auth_tag);
    if(encrypted_payload) ck_free(encrypted_payload);

    return encrypted_packet_len;
}

// if is_fuzz_with_dec_enc: convert the QUIC raw seed (encrypted) to a decrypted seed
// else: generate training data for the QUIC raw seed
// return 0 if successful, 1 if there is no QUIC packet found.
unsigned int convert_raw_to_decrypted_seed(u8 *raw_seed_filename, u8 *decrypted_seed_filename){
    unsigned char *buf = NULL;
    unsigned int buf_size = 0;
    unsigned char *mem = NULL;
    unsigned int byte_count = 0;
    unsigned int mem_count = 0;
    unsigned int mem_size = 1024;
    unsigned char *decrypted_buf = NULL;
    unsigned int decrypted_buf_len = 0;
    unsigned int packet_count = 0;
    unsigned int is_client = 1; // use with is_gen_train_data

    // read the raw_seed_file into buf
    struct stat st;
    s32 fd = open(raw_seed_filename, O_RDONLY);
    if (fd < 0) PFATAL("Unable to open '%s'", raw_seed_filename);

    // get file stats
    if (fstat(fd, &st) || !st.st_size) FATAL("Zero-sized seed file: %s", raw_seed_filename);
    if (st.st_size > MAX_FILE) FATAL("Seed file is too large (%u bytes max)", MAX_FILE);

    buf_size = st.st_size;
    buf = (char*)ck_alloc_nozero(buf_size);
    // read the input from file and store in secret
    ck_read(fd, buf, buf_size, raw_seed_filename);
    close(fd);

    if (strstr(raw_seed_filename, "Retry") != NULL) {
        is_retry = 1;
    }

    mem=(char *)ck_alloc(mem_size);

    // Check what type of QUIC packet is this
    while (byte_count < buf_size) {
        memcpy(&mem[mem_count], buf + byte_count++, 1);

        //Check if the region buffer length is 6 bytes (first few important bit to determine the QUIC packet header)
        if(mem_count == 5){
            unsigned int temp_count = 0;
            unsigned int bytes_to_skip = 0;
            unsigned int packet_num_offset = 0;
            unsigned int is_extracted_packet = 0;
            enum PacketType packet_type;
            enum frame_type;

            if(is_long_head_pkt(mem, mem_count)){
                // get packet type
                packet_type = get_packet_type(mem, mem_count);

                // the position that store the dcid length is 5
                unsigned int dcidLen = mem[5];
                unsigned int dcid_offset = byte_count;
                temp_count = 0;

                // go after dcid, which is the scid length
                while ((byte_count < buf_size) && (temp_count < (dcidLen + 1))) {
                    mem_count++;

                    // make sure mem have enough space
                    if(mem_count == mem_size) {
                        //enlarge the mem buffer
                        mem_size = mem_size * 2;
                        mem=(char *)ck_realloc(mem, mem_size);
                    }

                    memcpy(&mem[mem_count], buf + byte_count++, 1);
                    temp_count++;
                }

                // the position that store the scid length
                unsigned int scidLen = mem[mem_count];
                unsigned int scid_offset = byte_count;
                temp_count = 0;

                if(is_retry && packet_count == 0 && dcidLen <= CONN_ID_MAX_SIZE){
                    memcpy(quic_info.pre_init_dcid.cid, buf+dcid_offset, dcidLen);
                    quic_info.pre_init_dcid.cid_len = dcidLen;
                }

                // extract handshake packet dcid for later use when extracting 1-RTT packet from seed.
                // to generate training data, 
                if(packet_type == Handshake && quic_info.one_rtt_dcid_count == 0){
                    if(is_gen_train_data){
                        // when this packet is sent by client: the scid == client scid
                        if(scidLen == quic_info.current_initial_secret->client_source_conn_id_len){
                            if(memcmp(buf+scid_offset, quic_info.current_initial_secret->client_source_conn_id, scidLen) == 0){
                                add_cid(&quic_info.one_rtt_dcid, &quic_info.one_rtt_dcid_count, buf+dcid_offset, dcidLen);
                                add_cid(&quic_info.one_rtt_scid, &quic_info.one_rtt_scid_count, buf+scid_offset, scidLen);
                            }
                        }

                        // if dcid was not added above, then this packet is sent by server: the dcid == client scid
                        if(is_gen_train_data && quic_info.one_rtt_dcid_count == 0){
                            add_cid(&quic_info.one_rtt_dcid, &quic_info.one_rtt_dcid_count, buf+scid_offset, scidLen);
                            add_cid(&quic_info.one_rtt_scid, &quic_info.one_rtt_scid_count, buf+dcid_offset, dcidLen);
                        }

                    }else{
                        // do not need to check
                        add_cid(&quic_info.one_rtt_dcid, &quic_info.one_rtt_dcid_count, buf+dcid_offset, dcidLen);
                        add_cid(&quic_info.one_rtt_scid, &quic_info.one_rtt_scid_count, buf+scid_offset, scidLen);
                    }
                }

                // go after scid, which is the token length
                while ((byte_count < buf_size) && (temp_count < (scidLen + 1))) {
                    mem_count++;
                    
                    // make sure mem have enough space
                    if(mem_count == mem_size) {
                        //enlarge the mem buffer
                        mem_size = mem_size * 2;
                        mem=(char *)ck_realloc(mem, mem_size);
                    }

                    memcpy(&mem[mem_count], buf + byte_count++, 1);
                    temp_count++;
                }
                
                // do not need to extract the Initial secret for is_retry mode
                if(packet_type == Initial && !(is_retry && packet_count == 0) && !quic_info.stop_derive_initial_secret){
                    unsigned secret_exist = 0;

                    // check if the secret has been derived before?
                    if(quic_info.initial_secret != NULL){
                        for(int i=0; i<quic_info.initial_secret_count; i++){
                            // assume this is a Initial packet sent by the client
                            // check length
                            if(quic_info.initial_secret[i].client_source_conn_id_len == scidLen){
                                // check cid
                                if(memcmp(quic_info.initial_secret[i].client_source_conn_id, buf+scid_offset, scidLen) == 0){
                                    quic_info.current_initial_secret = &quic_info.initial_secret[i];
                                    secret_exist = 1;
                                    is_client = 1;
                                    break;
                                }
                            }
                            
                            // also make sure this is not the server's Initial packet (if yes, do not need to derive another key because they use the same Initial key)
                            // check length 
                            if(is_gen_train_data && quic_info.initial_secret[i].client_source_conn_id_len == dcidLen){
                                // check cid
                                if(memcmp(quic_info.initial_secret[i].client_source_conn_id, buf+dcid_offset, dcidLen) == 0){
                                    quic_info.current_initial_secret = &quic_info.initial_secret[i];
                                    secret_exist = 1;
                                    is_client = 0;
                                    break;
                                }
                            }
                        }
                    }

                    // if the secret has not been derived before, derive the secret
                    if(secret_exist == 0 && (scid_offset + scidLen) <= buf_size){
                        if(quic_info.initial_secret == NULL){
                            quic_info.initial_secret = (struct initial_secret *)ck_alloc(sizeof(struct initial_secret));
                        }else{
                            quic_info.initial_secret = (struct initial_secret *)ck_realloc(quic_info.initial_secret, (quic_info.initial_secret_count + 1)* sizeof(struct initial_secret));
                        }

                        // get first dcid
                        quic_info.initial_secret[quic_info.initial_secret_count].client_first_dest_conn_id_len = dcidLen;
                        memcpy(quic_info.initial_secret[quic_info.initial_secret_count].client_first_dest_conn_id, buf + dcid_offset, dcidLen);

                        // get scid
                        quic_info.initial_secret[quic_info.initial_secret_count].client_source_conn_id_len = scidLen;
                        memcpy(quic_info.initial_secret[quic_info.initial_secret_count].client_source_conn_id, buf + scid_offset, scidLen);

                        quic_info.initial_secret[quic_info.initial_secret_count].is_derived_initial_secret = 0;

                        // set the pointer before derive the Initial secret 
                        quic_info.current_initial_secret = &quic_info.initial_secret[quic_info.initial_secret_count];

                        // derive Initial secret
                        if(derive_secret(1, Initial) != 0 || derive_secret(0, Initial) != 0){
                            WARNF("Not able to get Initial keying material for decryption, Aborting...");
                            exit(EXIT_FAILURE);
                        }

                        quic_info.initial_secret_count++;
                    }
                }

                // derive Handshake and Traffic secrets
                if(!quic_info.is_derived_handshake_traffic_secret){
                    // Handshake secret and keys
                    if(derive_secret(1, Handshake) != 0 || derive_secret(0, Handshake) != 0){
                        WARNF("Not able to get Handshake keying material for decryption, Aborting...");
                        exit(EXIT_FAILURE);
                    }
                
                    // Traffic secret and keys
                    if(derive_secret(1, OneRTT) != 0 || derive_secret(0, OneRTT) != 0){
                        WARNF("Not able to get Handshake keying material for decryption, Aborting...");
                        exit(EXIT_FAILURE);
                    }

                    quic_info.is_derived_handshake_traffic_secret = 1;
                }

                // only Initial packets have token length and token
                if(packet_type == Initial){
                    // the position that store the token length
                    unsigned int tokenLength = mem[mem_count];
                    temp_count = 0;

                    // go after token, which is the first byte of packet length (plus 1)
                    while ((byte_count < buf_size) && (temp_count < (tokenLength + 1))) {
                        mem_count++;
                        
                        // make sure mem have enough space
                        if(mem_count == mem_size) {
                            //enlarge the mem buffer
                            mem_size = mem_size * 2;
                            mem=(char *)ck_realloc(mem, mem_size);
                        }

                        memcpy(&mem[mem_count], buf + byte_count++, 1);
                        temp_count++;
                    }
                }

                bytes_to_skip = variable_len_int_decode(mem, &mem_count, &mem_size, NULL, buf, &byte_count, buf_size);
                packet_num_offset = mem_count + 1;
                temp_count = 0;

                // extract the whole packet, if byte_to_skip + mem_count > mem_size, increase the size;
                // once extract the whole packet, decrypt the packet 
                while ((byte_count < buf_size) && (temp_count < bytes_to_skip)) {
                    mem_count++;

                    // make sure mem have enough space
                    if(mem_count == mem_size) {
                        //enlarge the mem buffer
                        mem_size = mem_size * 2;
                        mem=(char *)ck_realloc(mem, mem_size);
                    }

                    memcpy(&mem[mem_count], buf + byte_count++, 1);
                    temp_count++;
                }

                is_extracted_packet = 1;

                // when the position 7 (most significant bit) is not set, short header packet
            }else if(!(mem[0] & (1 << 7) && (mem[0] & (1 << 6)))){
                // short header (1-RTT)
                packet_type = OneRTT;

                // try to get the packet number offset, assuming this is a client sending packet
                if(packet_num_offset == 0){
                    packet_num_offset = get_one_rtt_pkt_num_offset(1, mem, mem_count + 1);
                }
                
                // try to get the packet number offset, assuming this is a server sending packet
                if(packet_num_offset == 0){
                    packet_num_offset = get_one_rtt_pkt_num_offset(0, mem, mem_count + 1);
                }

                while (byte_count < buf_size){
                    mem_count++;
                
                    // make sure mem have enough space
                    if(mem_count == mem_size) {
                        //enlarge the mem buffer
                        mem_size = mem_size * 2;
                        mem=(char *)ck_realloc(mem, mem_size);
                    }

                    memcpy(&mem[mem_count], buf + byte_count++, 1);

                    // break if the next few bytes are likely to be a new packet.
                    if(byte_count < buf_size){
                        if((byte_count + 1 + CONN_ID_MAX_SIZE) < buf_size){
                            if(is_short_head_pkt(buf + byte_count, 1+CONN_ID_MAX_SIZE, 0) == 1){
                                break;
                            }
                        }

                        if((byte_count + CHECK_LONG_HEAD_PKT_LEN) < buf_size){
                            if(is_long_head_pkt(buf + byte_count, CHECK_LONG_HEAD_PKT_LEN) == 1){
                                break;
                            }
                        } 
                        
                        if((byte_count + CHECK_VERSION_NEGO_PKT_LEN) < buf_size){
                            if(is_version_nego_pkt(buf + byte_count, CHECK_VERSION_NEGO_PKT_LEN) == 1){
                                break;
                            }
                        }
                    }
                }

                is_extracted_packet = 1;
            }

            if(is_extracted_packet){
                
                // only use to test the decryption functions on the seed, comment/remove this when fuzzing.
                // decrypt the packet and store them
                unsigned char *decrypted_packet = NULL;
                unsigned int decrypted_packet_len; 
                
                // if is in_retry mode, do not decrypt the first Initial packet, then the rest is same as normal mode
                if(!(is_retry && packet_count == 0)){
                    if(is_gen_train_data && !is_client){
                        decrypted_packet_len = decrypt_packet(0, mem, mem_count+1, packet_num_offset, packet_type, &decrypted_packet, NULL);
                        is_client = 1;
                    }else {
                        decrypted_packet_len = decrypt_packet(1, mem, mem_count+1, packet_num_offset, packet_type, &decrypted_packet, NULL);
                    }

                    // save the decrypted packet into decrypted_buf
                    if(decrypted_packet){
                        packet_count++;

                        if(!is_gen_train_data){
                            if(decrypted_buf == NULL){
                                decrypted_buf = (char*)ck_alloc_nozero(decrypted_packet_len);
                            }else{
                                decrypted_buf = (char*)ck_realloc(decrypted_buf, decrypted_buf_len + decrypted_packet_len);
                            }

                            memcpy(decrypted_buf+decrypted_buf_len, decrypted_packet, decrypted_packet_len);
                            decrypted_buf_len += decrypted_packet_len;   
                        }

                        ck_free(decrypted_packet);
                    }
                }else{
                    // In retry mode, do not need to decrypt or encrypt because this is just to trigger Retry packet
                    packet_count++;
                    int enc_init_pkt_len = mem_count+1;

                    if(!is_gen_train_data){
                        if(decrypted_buf == NULL){
                            decrypted_buf = (char*)ck_alloc_nozero(enc_init_pkt_len);
                        }else{
                            decrypted_buf = (char*)ck_realloc(decrypted_buf, decrypted_buf_len + enc_init_pkt_len);
                        }

                        memcpy(decrypted_buf+decrypted_buf_len, mem, enc_init_pkt_len);
                        decrypted_buf_len += enc_init_pkt_len;   
                    }
                }

                //Check if the last byte has been reached
                if (byte_count < buf_size) {
                    mem_count = 0;
                }
            }
        } else {
            mem_count++;

            //Check if the last byte has been reached
            if (byte_count == buf_size) {
                break;
            }

            if (mem_count == mem_size) {
                //enlarge the mem buffer
                mem_size = mem_size * 2;
                mem=(char *)ck_realloc(mem, mem_size);
            }
        }
    }

    if (mem) ck_free(mem);
    if(buf) ck_free(buf);

    // in case there is no packet detected in the seed
    if (packet_count == 0) {
        WARNF("There is no QUIC packet found in the given seed: %s.", raw_seed_filename);
        return 1;
    } else if(!is_gen_train_data && decrypted_seed_filename != NULL){
    //} else{
        // save to decrypted_seed_file
        fd = open(decrypted_seed_filename, O_WRONLY | O_CREAT, 0600);
        if (fd < 0) PFATAL("Unable to create file '%s'", decrypted_seed_filename);
        ck_write(fd, decrypted_buf, decrypted_buf_len, decrypted_seed_filename);
        close(fd);
        if(decrypted_buf) ck_free(decrypted_buf);
    }

    return 0;
}