#include "authen.h"
#include "io.h"

#include <stdlib.h>
#include <string.h>

#define TAC_PLUS_AUTHEN_LOGIN 0x01

#define TAC_PLUS_AUTHEN_TYPE_ASCII 0x01

#define TAC_PLUS_AUTHEN_STATUS_PASS 0x01
#define TAC_PLUS_AUTHEN_STATUS_FAIL 0x02
#define TAC_PLUS_AUTHEN_STATUS_GETUSER 0x04
#define TAC_PLUS_AUTHEN_STATUS_GETPASS 0x05
#define TAC_PLUS_AUTHEN_STATUS_ERROR 0x07

#define TAC_PLUS_REPLY_FLAG_NOECHO 0x01
#define TAC_PLUS_CONTINUE_FLAG_ABORT 0x01

typedef struct {
    uint8_t action;
    uint8_t authen_type;
    char user[TAC_MAX_USERNAME_LEN];
} start_fields_t;

static int parse_start(const uint8_t *body, size_t len, start_fields_t *out)
{
    if (len < 8) {
        return -1;
    }
    out->action = body[0];
    out->authen_type = body[2];
    uint8_t user_len = body[4];
    uint8_t port_len = body[5];
    uint8_t rem_addr_len = body[6];
    uint8_t data_len = body[7];

    size_t needed = 8 + (size_t)user_len + port_len + rem_addr_len + data_len;
    if (needed > len) {
        return -1;
    }

    size_t copy_len = user_len < sizeof(out->user) - 1 ? user_len : sizeof(out->user) - 1;
    memcpy(out->user, body + 8, copy_len);
    out->user[copy_len] = '\0';
    return 0;
}

static int parse_continue(const uint8_t *body, size_t len, char *msg, size_t msg_cap, uint8_t *abort_flag)
{
    if (len < 5) {
        return -1;
    }
    uint16_t user_msg_len = ((uint16_t)body[0] << 8) | body[1];
    uint16_t data_len = ((uint16_t)body[2] << 8) | body[3];
    uint8_t flags = body[4];

    size_t needed = 5 + (size_t)user_msg_len + data_len;
    if (needed > len) {
        return -1;
    }

    size_t copy_len = user_msg_len < msg_cap - 1 ? user_msg_len : msg_cap - 1;
    memcpy(msg, body + 5, copy_len);
    msg[copy_len] = '\0';
    *abort_flag = flags & TAC_PLUS_CONTINUE_FLAG_ABORT;
    return 0;
}

static int send_reply(int fd, const char *key, tac_header_t *hdr, uint8_t status, uint8_t flags,
                       const char *server_msg)
{
    hdr->seq_no++;

    size_t msg_len = server_msg ? strlen(server_msg) : 0;
    size_t body_len = 6 + msg_len;
    uint8_t *body = calloc(1, body_len);
    if (!body) {
        return -1;
    }

    body[0] = status;
    body[1] = flags;
    body[2] = (uint8_t)(msg_len >> 8);
    body[3] = (uint8_t)(msg_len);
    body[4] = 0;
    body[5] = 0;
    if (msg_len > 0) {
        memcpy(body + 6, server_msg, msg_len);
    }

    hdr->length = (uint32_t)body_len;
    int rc = tac_write_packet(fd, key, hdr, body, body_len);
    free(body);
    return rc;
}

static int read_continue(int fd, const char *key, tac_header_t *hdr, char *msg, size_t msg_cap,
                          uint8_t *abort_flag)
{
    uint8_t *body = NULL;
    size_t body_len = 0;
    if (tac_read_packet(fd, key, hdr, &body, &body_len) != 0) {
        free(body);
        return -1;
    }
    if (hdr->type != TAC_PLUS_AUTHEN) {
        free(body);
        return -1;
    }
    int rc = parse_continue(body, body_len, msg, msg_cap, abort_flag);
    free(body);
    return rc;
}

void tac_authen_handle(int fd, const char *key, const tac_config_t *cfg,
                        tac_header_t *hdr, const uint8_t *body, size_t body_len)
{
    start_fields_t start;
    if (parse_start(body, body_len, &start) != 0) {
        send_reply(fd, key, hdr, TAC_PLUS_AUTHEN_STATUS_ERROR, 0, "malformed START packet");
        return;
    }

    if (start.action != TAC_PLUS_AUTHEN_LOGIN || start.authen_type != TAC_PLUS_AUTHEN_TYPE_ASCII) {
        send_reply(fd, key, hdr, TAC_PLUS_AUTHEN_STATUS_ERROR, 0, "only ASCII login is supported");
        return;
    }

    char username[TAC_MAX_USERNAME_LEN];
    strncpy(username, start.user, sizeof(username) - 1);
    username[sizeof(username) - 1] = '\0';

    uint8_t abort_flag = 0;
    if (username[0] == '\0') {
        if (send_reply(fd, key, hdr, TAC_PLUS_AUTHEN_STATUS_GETUSER, 0, "Username: ") != 0) {
            return;
        }
        if (read_continue(fd, key, hdr, username, sizeof(username), &abort_flag) != 0 || abort_flag) {
            return;
        }
    }

    char password[TAC_MAX_PASSWORD_LEN];
    if (send_reply(fd, key, hdr, TAC_PLUS_AUTHEN_STATUS_GETPASS, TAC_PLUS_REPLY_FLAG_NOECHO, "Password: ") != 0) {
        return;
    }
    if (read_continue(fd, key, hdr, password, sizeof(password), &abort_flag) != 0 || abort_flag) {
        return;
    }

    const tac_user_t *u = tac_config_find_user(cfg, username);
    if (u && strcmp(u->password, password) == 0) {
        send_reply(fd, key, hdr, TAC_PLUS_AUTHEN_STATUS_PASS, 0, "");
    } else {
        send_reply(fd, key, hdr, TAC_PLUS_AUTHEN_STATUS_FAIL, 0, "Authentication failed");
    }
}
