#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "alloc-inl.h"
#include "debug.h"

#include "quic.h"

// // // extern from the afl-fuzz.c
// extern u8 is_gen_train_data;
u8 is_quic = 0;
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