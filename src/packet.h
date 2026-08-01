/* TACACS+ packet framing per RFC 8907 section 4. */
#ifndef TAC_PACKET_H
#define TAC_PACKET_H

#include <stddef.h>
#include <stdint.h>

#define TAC_PLUS_MAJOR_VER 0xc
#define TAC_PLUS_MINOR_VER_DEFAULT 0x0
#define TAC_PLUS_MINOR_VER_ONE 0x1

#define TAC_PLUS_AUTHEN 0x01
#define TAC_PLUS_AUTHOR 0x02
#define TAC_PLUS_ACCT 0x03

#define TAC_PLUS_UNENCRYPTED_FLAG 0x01
#define TAC_PLUS_SINGLE_CONNECT_FLAG 0x04

#define TAC_HEADER_SIZE 12

/* Largest body this server will accept; guards against bogus/hostile
 * length fields before an allocation is attempted. */
#define TAC_MAX_BODY_SIZE 65535

typedef struct {
    uint8_t version;
    uint8_t type;
    uint8_t seq_no;
    uint8_t flags;
    uint32_t session_id;
    uint32_t length;
} tac_header_t;

void tac_header_encode(const tac_header_t *hdr, uint8_t out[TAC_HEADER_SIZE]);
int tac_header_decode(const uint8_t in[TAC_HEADER_SIZE], tac_header_t *hdr);

/* XORs body in place with the MD5 pseudo-pad derived from the header
 * fields and the shared secret key. Symmetric: call again to reverse. */
void tac_crypt(const tac_header_t *hdr, const char *key, uint8_t *body, size_t body_len);

#endif
