#include "acct.h"
#include "io.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TAC_PLUS_ACCT_STATUS_SUCCESS 0x01
#define TAC_PLUS_ACCT_STATUS_ERROR 0x02

static int parse_request(const uint8_t *body, size_t len, char *user, size_t user_cap)
{
    if (len < 9) {
        return -1;
    }
    uint8_t user_len = body[5];
    uint8_t port_len = body[6];
    uint8_t rem_addr_len = body[7];
    uint8_t arg_cnt = body[8];

    if ((size_t)9 + arg_cnt > len) {
        return -1;
    }
    const uint8_t *arg_lens = body + 9;
    size_t offset = 9 + arg_cnt;

    size_t needed = offset + (size_t)user_len + port_len + rem_addr_len;
    if (needed > len) {
        return -1;
    }

    size_t copy_len = user_len < user_cap - 1 ? user_len : user_cap - 1;
    memcpy(user, body + offset, copy_len);
    user[copy_len] = '\0';

    offset += (size_t)user_len + port_len + rem_addr_len;
    for (uint8_t i = 0; i < arg_cnt; i++) {
        if (offset + arg_lens[i] > len) {
            return -1;
        }
        offset += arg_lens[i];
    }
    return 0;
}

static int send_reply(int fd, const char *key, tac_header_t *hdr, uint8_t status, const char *server_msg)
{
    hdr->seq_no++;

    size_t msg_len = server_msg ? strlen(server_msg) : 0;
    size_t body_len = 5 + msg_len;
    uint8_t *out = calloc(1, body_len);
    if (!out) {
        return -1;
    }

    out[0] = (uint8_t)(msg_len >> 8);
    out[1] = (uint8_t)(msg_len);
    out[2] = 0;
    out[3] = 0;
    out[4] = status;
    if (msg_len > 0) {
        memcpy(out + 5, server_msg, msg_len);
    }

    hdr->length = (uint32_t)body_len;
    int rc = tac_write_packet(fd, key, hdr, out, body_len);
    free(out);
    return rc;
}

void tac_acct_handle(int fd, const char *key, const tac_config_t *cfg,
                      tac_header_t *hdr, const uint8_t *body, size_t body_len)
{
    (void)cfg;

    char user[TAC_MAX_USERNAME_LEN] = {0};
    if (body_len < 1 || parse_request(body, body_len, user, sizeof(user)) != 0) {
        send_reply(fd, key, hdr, TAC_PLUS_ACCT_STATUS_ERROR, "malformed REQUEST packet");
        return;
    }

    uint8_t flags = body[0];
    fprintf(stderr, "tacacs: accounting: user=%s flags=0x%02x\n", user, flags);
    send_reply(fd, key, hdr, TAC_PLUS_ACCT_STATUS_SUCCESS, "");
}
