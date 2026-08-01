#include "io.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int read_full(int fd, uint8_t *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = read(fd, buf + off, len - off);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            return -1; /* peer closed the connection */
        }
        off += (size_t)n;
    }
    return 0;
}

static int write_full(int fd, const uint8_t *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, buf + off, len - off);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

int tac_read_packet(int fd, const char *key, tac_header_t *hdr, uint8_t **body_out, size_t *body_len_out)
{
    uint8_t hdr_buf[TAC_HEADER_SIZE];
    if (read_full(fd, hdr_buf, sizeof(hdr_buf)) != 0) {
        return -1;
    }
    if (tac_header_decode(hdr_buf, hdr) != 0) {
        return -1;
    }

    uint8_t *body = NULL;
    if (hdr->length > 0) {
        body = malloc(hdr->length);
        if (!body) {
            return -1;
        }
        if (read_full(fd, body, hdr->length) != 0) {
            free(body);
            return -1;
        }
        if (!(hdr->flags & TAC_PLUS_UNENCRYPTED_FLAG)) {
            tac_crypt(hdr, key, body, hdr->length);
        }
    }

    *body_out = body;
    *body_len_out = hdr->length;
    return 0;
}

int tac_write_packet(int fd, const char *key, const tac_header_t *hdr, const uint8_t *body, size_t body_len)
{
    uint8_t hdr_buf[TAC_HEADER_SIZE];
    tac_header_encode(hdr, hdr_buf);

    uint8_t *out_body = NULL;
    if (body_len > 0) {
        out_body = malloc(body_len);
        if (!out_body) {
            return -1;
        }
        memcpy(out_body, body, body_len);
        if (!(hdr->flags & TAC_PLUS_UNENCRYPTED_FLAG)) {
            tac_crypt(hdr, key, out_body, body_len);
        }
    }

    int rc = 0;
    if (write_full(fd, hdr_buf, sizeof(hdr_buf)) != 0) {
        rc = -1;
    } else if (body_len > 0 && write_full(fd, out_body, body_len) != 0) {
        rc = -1;
    }

    free(out_body);
    return rc;
}
