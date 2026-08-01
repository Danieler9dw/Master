#include "eap_attr.h"

#include <string.h>

void eap_attr_iter_init(eap_attr_iter_t *iter, const uint8_t *buf, size_t len)
{
    iter->buf = buf;
    iter->len = len;
    iter->offset = 0;
}

int eap_attr_iter_next(eap_attr_iter_t *iter, eap_attr_t *out)
{
    if (iter->offset == iter->len) {
        return 0;
    }
    if (iter->offset + 2 > iter->len) {
        return -1; /* truncated attribute header */
    }

    uint8_t type = iter->buf[iter->offset];
    uint8_t length_words = iter->buf[iter->offset + 1];
    if (length_words == 0) {
        return -1; /* a Length of 0 cannot even hold Type+Length themselves */
    }

    size_t attr_total = (size_t)length_words * 4;
    if (iter->offset + attr_total > iter->len) {
        return -1; /* truncated attribute value */
    }

    out->type = type;
    out->value = iter->buf + iter->offset + 2;
    out->value_len = attr_total - 2;
    iter->offset += attr_total;
    return 1;
}

int eap_attr_append(uint8_t *out, size_t out_cap, size_t *out_offset, uint8_t type,
                     const uint8_t *value, size_t value_len)
{
    size_t unpadded = 2 + value_len;
    size_t padded = (unpadded + 3) & ~(size_t)3;
    size_t length_words = padded / 4;
    if (length_words > 255) {
        return -1;
    }
    if (*out_offset + padded > out_cap) {
        return -1;
    }

    uint8_t *p = out + *out_offset;
    p[0] = type;
    p[1] = (uint8_t)length_words;
    if (value_len > 0) {
        memcpy(p + 2, value, value_len);
    }
    size_t pad_bytes = padded - unpadded;
    if (pad_bytes > 0) {
        memset(p + 2 + value_len, 0, pad_bytes);
    }

    *out_offset += padded;
    return 0;
}
