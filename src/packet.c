#include "packet.h"
#include "md5.h"
#include <string.h>

void tac_header_encode(const tac_header_t *hdr, uint8_t out[TAC_HEADER_SIZE])
{
    out[0] = hdr->version;
    out[1] = hdr->type;
    out[2] = hdr->seq_no;
    out[3] = hdr->flags;
    out[4] = (uint8_t)(hdr->session_id >> 24);
    out[5] = (uint8_t)(hdr->session_id >> 16);
    out[6] = (uint8_t)(hdr->session_id >> 8);
    out[7] = (uint8_t)(hdr->session_id);
    out[8] = (uint8_t)(hdr->length >> 24);
    out[9] = (uint8_t)(hdr->length >> 16);
    out[10] = (uint8_t)(hdr->length >> 8);
    out[11] = (uint8_t)(hdr->length);
}

int tac_header_decode(const uint8_t in[TAC_HEADER_SIZE], tac_header_t *hdr)
{
    hdr->version = in[0];
    hdr->type = in[1];
    hdr->seq_no = in[2];
    hdr->flags = in[3];
    hdr->session_id = ((uint32_t)in[4] << 24) | ((uint32_t)in[5] << 16) |
                       ((uint32_t)in[6] << 8) | (uint32_t)in[7];
    hdr->length = ((uint32_t)in[8] << 24) | ((uint32_t)in[9] << 16) |
                  ((uint32_t)in[10] << 8) | (uint32_t)in[11];

    if (hdr->type != TAC_PLUS_AUTHEN && hdr->type != TAC_PLUS_AUTHOR &&
        hdr->type != TAC_PLUS_ACCT) {
        return -1;
    }
    if (hdr->length > TAC_MAX_BODY_SIZE) {
        return -1;
    }
    return 0;
}

void tac_crypt(const tac_header_t *hdr, const char *key, uint8_t *body, size_t body_len)
{
    if (body_len == 0) {
        return;
    }

    uint8_t session_id_be[4] = {
        (uint8_t)(hdr->session_id >> 24),
        (uint8_t)(hdr->session_id >> 16),
        (uint8_t)(hdr->session_id >> 8),
        (uint8_t)(hdr->session_id),
    };
    size_t key_len = strlen(key);

    uint8_t prev_digest[16];
    int have_prev = 0;
    size_t offset = 0;

    while (offset < body_len) {
        md5_ctx_t ctx;
        md5_init(&ctx);
        md5_update(&ctx, session_id_be, sizeof(session_id_be));
        md5_update(&ctx, (const uint8_t *)key, key_len);
        md5_update(&ctx, &hdr->version, 1);
        md5_update(&ctx, &hdr->seq_no, 1);
        if (have_prev) {
            md5_update(&ctx, prev_digest, sizeof(prev_digest));
        }

        uint8_t digest[16];
        md5_final(&ctx, digest);

        size_t chunk = body_len - offset;
        if (chunk > sizeof(digest)) {
            chunk = sizeof(digest);
        }
        for (size_t i = 0; i < chunk; i++) {
            body[offset + i] ^= digest[i];
        }

        memcpy(prev_digest, digest, sizeof(digest));
        have_prev = 1;
        offset += chunk;
    }
}
