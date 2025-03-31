#ifndef __QUIC_H
#define __QUIC_H 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <stdint.h>

// declare here, define in quic.c
extern u8 is_quic;
extern u8 is_fuzz_with_dec_enc; // set this to 1 if fuzzing with encrypted raw seed
extern u8 is_gen_train_data; // set this to 1 for generating LLM training data or testing
extern u8 is_replay; // set this to not check Initial secret with cid when using aflnet-replay

enum QuicVersion{
    No_Assigned = 0x00,
    Version_1 = 0x01,
    Draft_29 = 0x1D,
};

enum PacketType{
    Initial = 0x00,
    ZeroRTT = 0x01,
    Handshake = 0x02,
    Retry = 0x03,
    OneRTT = 0x04, // temporary use ZeroRTT as OneRTT because I only reserve 2 bits in the response code, so 4 packet type only.
    Error = 0x05
};

// // QUIC versions value
static unsigned char version_1_value[] = {0x00, 0x00, 0x00, 0x01};
static unsigned char draft_29_value[] = {0xff, 0x00, 0x00, 0x1d};

#define SECRET_SIZE 32
#define KEY_SIZE 16
#define IV_SIZE 12
#define HP_SIZE 16
#define SAMPLE_SIZE 16
#define AUTH_TAG_SIZE 16
#define MAX_TRUNCATED_PACKET_NUM_SIZE 4
#define CANDIDATE_PACKET_NUM_SIZE 8
#define CONN_ID_MAX_SIZE 20
#define CHECK_VERSION_NEGO_PKT_LEN 5
#define CHECK_LONG_HEAD_PKT_LEN 5

struct endpoint_secret{
    unsigned char secret[SECRET_SIZE];
    unsigned char key[KEY_SIZE];
    unsigned char iv[IV_SIZE];
    unsigned char hp[HP_SIZE];
};

// for Initial secret because the seed dir may contain several raw file with different Initial secret
struct initial_secret{
    unsigned char client_first_dest_conn_id[CONN_ID_MAX_SIZE];
    unsigned int client_first_dest_conn_id_len;
    unsigned char client_source_conn_id[CONN_ID_MAX_SIZE];
    unsigned int client_source_conn_id_len;
    unsigned char initial_secret[SECRET_SIZE];
    unsigned int is_derived_initial_secret;
    struct endpoint_secret client_initial_secret;
    struct endpoint_secret server_initial_secret;
};

struct connection_id{
    unsigned char cid[CONN_ID_MAX_SIZE];
    unsigned int cid_len;
};

// QUIC-Fuzz: store the current server connection id
struct quic_conn_info{
    enum QuicVersion quic_version;

    // secrets
    unsigned int is_derived_handshake_traffic_secret;
    // array to store initial_secrets from different seed
    unsigned int stop_derive_initial_secret;
    struct initial_secret *initial_secret;
    unsigned int initial_secret_count;
    struct initial_secret *current_initial_secret;
    // struct endpoint_secret *client_initial_secret;
    struct endpoint_secret client_handshake_secret;
    struct endpoint_secret client_traffic_secret;
    // struct endpoint_secret *server_initial_secret;
    struct endpoint_secret server_handshake_secret;
    struct endpoint_secret server_traffic_secret;

    // the server source connection id, the one picked by the server (hardcoded in the server)
    struct connection_id *one_rtt_dcid; // server cid
    unsigned int one_rtt_dcid_count;
    struct connection_id *one_rtt_scid; // client/fuzzer cid
    unsigned int one_rtt_scid_count;

    // packet number space
    uint64_t client_expected_initial_num;
    uint64_t client_expected_handshake_num;
    uint64_t client_expected_traffic_num;
    uint64_t server_expected_initial_num;
    uint64_t server_expected_handshake_num;
    uint64_t server_expected_traffic_num;
};

extern struct quic_conn_info quic_info;

void print_byte_string(unsigned char *byte_str, unsigned int byte_str_size);
void print_byte_string_to_log(const char *file, const char *start_extra, const char *end_extra, unsigned char *byte_str, unsigned int byte_str_size);
void reset_quic_info();
void init_quic_info();
void free_quic_info();
void add_cid(struct connection_id **cid_struct_array, unsigned int *cid_struct_array_size, unsigned char *cid, unsigned int len);

// decryption and decoding
unsigned int variable_len_int_encode(unsigned char *mem, unsigned int offset, unsigned int len_field_len, unsigned int packet_len);
unsigned int variable_len_int_decode(unsigned char *mem, unsigned int *mem_count, unsigned int *mem_size, unsigned int *cur_end, unsigned char* buf, unsigned int *byte_count, unsigned int buf_size);

// for parsing quic packet
unsigned int is_version_nego_pkt(unsigned char *byte_stream, unsigned int byte_stream_len);
unsigned int is_long_head_pkt(unsigned char *byte_stream, unsigned int byte_stream_len);
unsigned int is_short_head_pkt(unsigned char *byte_stream, unsigned int byte_stream_len, unsigned int is_recv);
#endif /* __QUIC_H */