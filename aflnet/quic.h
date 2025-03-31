#ifndef __QUIC_H
#define __QUIC_H 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <stdint.h>

// QUIC-Fuzz: ADDED HERE to decrypt Quic packet.
#include <openssl/kdf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/aes.h>
#include <errno.h>

// declare here, define in quic.c
extern u8 is_quic;
extern u8 is_retry;
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

enum FrameType{
	Padding = 0x00,
	Ping = 0x01,
	Ack = 0x02,
	AckEcn = 0x03,
	ResetStream = 0x04,
	StopSending = 0x05,
	Crypto = 0x06,
	NewToken = 0x07,
	// Stream = 0x08...0x0f
	MaxData = 0x10,
	MaxStreamData = 0x11,
	MaxStreamsBidirectionalStreams = 0x12,
	MaxStreamsUnidirectionalStreams = 0x13,
	DataBlocked = 0x14,
	StreamDataBlocked = 0x15,
	StreamsBlockedBidirectionalStreams = 0x16,
	StreamsBlockedUnidirectionalStreams = 0x17,
	NewConnectionID = 0x18,
	RetireConnectionID = 0x19,
	PathChallenge = 0x1a,
	PathResponse = 0x1b,
	ConnectionClose = 0x1c,
	ConnectionCloseApplication = 0x1d,
	HandshakeDone = 0x1e,
};

// QUIC versions value
static unsigned char version_1_value[] = {0x00, 0x00, 0x00, 0x01};
static unsigned char draft_29_value[] = {0xff, 0x00, 0x00, 0x1d};

// salt to derive initial secret and labels to expand the secret to get key, iv and hp
static unsigned char initial_salt[] = {0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a};
static unsigned char initial_salt_draft_29[] = {0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99};
static unsigned char client_label[] = {0x00, 0x20, 0x0f, 0x74, 0x6c, 0x73, 0x31, 0x33, 0x20, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x20, 0x69, 0x6e, 0x00};
static unsigned char server_label[] = {0x00, 0x20, 0x0f, 0x74, 0x6c, 0x73, 0x31, 0x33, 0x20, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x69, 0x6e, 0x00};
static unsigned char quic_key_label[] = {0x00, 0x10, 0x0e, 0x74, 0x6c, 0x73, 0x31, 0x33, 0x20, 0x71, 0x75, 0x69, 0x63, 0x20, 0x6b, 0x65, 0x79, 0x00};
static unsigned char quic_iv_label[] = {0x00, 0x0c, 0x0d, 0x74, 0x6c, 0x73, 0x31, 0x33, 0x20, 0x71, 0x75, 0x69, 0x63, 0x20, 0x69, 0x76, 0x00};
static unsigned char quic_hp_label[] = {0x00, 0x10, 0x0d, 0x74, 0x6c, 0x73, 0x31, 0x33, 0x20, 0x71, 0x75, 0x69, 0x63, 0x20, 0x68, 0x70, 0x00};

//serverHandshakeTrafficSecret in picotls
// ADDED HERE to hardcode the handshake keys (hardcode so that server and client use the same secret)
static unsigned char handshake_secret[] = {0x87, 0xbf, 0xf5, 0x41, 0x83, 0x10, 0x23, 0x8f, 
                                            0xe4, 0xff, 0x87, 0x57, 0x26, 0x20, 0xbb, 0x50, 
                                            0x4d, 0x79, 0x11, 0x1e, 0x54, 0x54, 0x4f, 0x37, 
                                            0x5d, 0x0d, 0xee, 0x58, 0x34, 0xee, 0x1f, 0x96};
    
//serverTrafficSecret in picotls
// ADDED HERE to hardcode the 1-RTT keys (hardcode so that server and client use the same secret)
static unsigned char traffic_secret[] = {0x2b, 0x4e, 0x6d, 0xd9, 0xdc, 0xa8, 0x1e, 0x8b, 
                                    0xf6, 0xc4, 0xb3, 0x7b, 0x48, 0x9a, 0x97, 0x02,
                                    0xeb, 0x5c, 0xd1, 0xab, 0x20, 0x09, 0xcd, 0xad, 
                                    0x50, 0x0d, 0x09, 0xec, 0xf9, 0x22, 0x81, 0x09};


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
    // this is when testing retry mode: remember the dcid so that fuzzer know to not encrypt the Initial packet that trigger the Retry from server
    struct connection_id pre_init_dcid;
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
void set_stop_derive_initial_secret();
void add_cid(struct connection_id **cid_struct_array, unsigned int *cid_struct_array_size, unsigned char *cid, unsigned int len);

// decryption and decoding
unsigned int variable_len_int_encode(unsigned char *mem, unsigned int offset, unsigned int len_field_len, unsigned int packet_len);
unsigned int variable_len_int_decode(unsigned char *mem, unsigned int *mem_count, unsigned int *mem_size, unsigned int *cur_end, unsigned char* buf, unsigned int *byte_count, unsigned int buf_size);
int derive_secret(int is_client, enum PacketType packet_type);
void write_secrets_to_file(u8 *filename);
void read_secrets_from_file(u8 *filename);
uint64_t decode_packet_number(int is_client, enum PacketType packet_type, uint32_t truncated_packet_num, unsigned int packet_num_bits);
unsigned int get_header_protection_mask(int is_client, enum PacketType packet_type, unsigned char *sample, unsigned char *mask);
unsigned int apply_header_protection(int is_client, unsigned char *packet, enum PacketType packet_type, unsigned int packet_num_offset);
unsigned int remove_header_protection(int is_client, unsigned char *packet, enum PacketType packet_type, unsigned int packet_num_offset, uint32_t *truncated_packet_num);
unsigned char *get_nonce(int is_client, uint64_t candidate_packet_num, enum PacketType packet_type);
struct endpoint_secret *get_end_point_secret(int is_client, enum PacketType packet_type);
uint64_t get_candidate_packet_num(unsigned char *packet, unsigned int packet_num_offset);
unsigned int get_associate_data(unsigned char *packet, unsigned int packet_num_offset, unsigned char **associate_data);
unsigned int get_payload(unsigned char *packet, unsigned int packet_len, unsigned int packet_num_offset, unsigned char **payload);
unsigned int get_correct_current_initial_secret(unsigned char *packet, unsigned int packet_len);
unsigned int encrypt_payload(int is_client, enum PacketType packet_type, uint64_t candidate_packet_num, unsigned char *associate_data, unsigned int associate_data_len, unsigned char *payload, unsigned int payload_len, unsigned int packet_num_offset, unsigned char *encrypted_payload, unsigned char *auth_tag);
unsigned int decrypt_payload(int is_client, enum PacketType packet_type, uint64_t candidate_packet_num, unsigned char *associate_data, unsigned int associate_data_len, unsigned char *payload, unsigned int payload_len, unsigned char *decrypted_payload);

// for parsing quic packet
unsigned int get_one_rtt_pkt_num_offset(unsigned int is_send, unsigned char *byte_stream, unsigned int byte_stream_len);
unsigned int is_version_nego_pkt(unsigned char *byte_stream, unsigned int byte_stream_len);
unsigned int is_long_head_pkt(unsigned char *byte_stream, unsigned int byte_stream_len);
unsigned int is_short_head_pkt(unsigned char *byte_stream, unsigned int byte_stream_len, unsigned int is_recv);

// parse quic frames
unsigned int parse_ack(unsigned int frames, unsigned char *decrypted_payload, unsigned int decrypted_payload_len, unsigned int *decrypted_payload_count);
unsigned int parse_crypto(unsigned int frames, unsigned char *decrypted_payload, unsigned int decrypted_payload_len, unsigned int *decrypted_payload_count);
unsigned int parse_new_token(unsigned int frames, unsigned char *decrypted_payload, unsigned int decrypted_payload_len, unsigned int *decrypted_payload_count);
unsigned int parse_new_connection_id(unsigned int frames, unsigned char *decrypted_payload, unsigned int decrypted_payload_len, unsigned int *decrypted_payload_count);
unsigned int parse_connection_close(unsigned int frames, unsigned char *decrypted_payload, unsigned int decrypted_payload_len, unsigned int *decrypted_payload_count);


unsigned int get_frame_type(unsigned char *decrypted_payload, unsigned int decrypted_payload_len);
unsigned int decrypt_packet(int is_client, unsigned char *packet, unsigned int packet_len, unsigned int packet_num_offset, enum PacketType packet_type, unsigned char **decrypted_packet, unsigned int *frame);
unsigned int encrypt_packet(int is_client, unsigned char *packet, unsigned int packet_len, unsigned int packet_num_offset, enum PacketType packet_type, unsigned char **encrypted_packet);

unsigned int convert_raw_to_decrypted_seed(u8 *raw_seed_filename, u8 *decrypted_seed_filename);
#endif /* __QUIC_H */