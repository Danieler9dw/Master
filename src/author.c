#include "author.h"
#include "io.h"

#include <stdlib.h>
#include <string.h>

#define TAC_PLUS_AUTHOR_STATUS_PASS_ADD 0x01
#define TAC_PLUS_AUTHOR_STATUS_FAIL 0x10
#define TAC_PLUS_AUTHOR_STATUS_ERROR 0x11

static int parse_request(const uint8_t *body, size_t len, char *user, size_t user_cap)
{
    if (len < 8) {
        return -1;
    }
    uint8_t user_len = body[4];
    uint8_t port_len = body[5];
    uint8_t rem_addr_len = body[6];
    uint8_t arg_cnt = body[7];

    if ((size_t)8 + arg_cnt > len) {
        return -1;
    }
    const uint8_t *arg_lens = body + 8;
    size_t offset = 8 + arg_cnt;

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

static int send_response(int fd, const char *key, tac_header_t *hdr, uint8_t status, const char *server_msg)
{
    hdr->seq_no++;

    size_t msg_len = server_msg ? strlen(server_msg) : 0;
    size_t body_len = 6 + msg_len;
    uint8_t *out = calloc(1, body_len);
    if (!out) {
        return -1;
    }

    out[0] = status;
    out[1] = 0; /* arg_cnt: this server never adds/replaces arguments */
    out[2] = (uint8_t)(msg_len >> 8);
    out[3] = (uint8_t)(msg_len);
    out[4] = 0;
    out[5] = 0;
    if (msg_len > 0) {
        memcpy(out + 6, server_msg, msg_len);
    }

    hdr->length = (uint32_t)body_len;
    int rc = tac_write_packet(fd, key, hdr, out, body_len);
    free(out);
    return rc;
}

void tac_author_handle(int fd, const char *key, const tac_config_t *cfg,
                        tac_header_t *hdr, const uint8_t *body, size_t body_len)
{
    char user[TAC_MAX_USERNAME_LEN];
    if (parse_request(body, body_len, user, sizeof(user)) != 0) {
        send_response(fd, key, hdr, TAC_PLUS_AUTHOR_STATUS_ERROR, "malformed REQUEST packet");
        return;
    }

    if (tac_config_find_user(cfg, user)) {
        send_response(fd, key, hdr, TAC_PLUS_AUTHOR_STATUS_PASS_ADD, "");
    } else {
        send_response(fd, key, hdr, TAC_PLUS_AUTHOR_STATUS_FAIL, "unknown user");
    }
}
