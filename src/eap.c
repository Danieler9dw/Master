#include "eap.h"

#include <string.h>

static size_t encode_common(uint8_t code, uint8_t identifier, uint8_t type,
                             const uint8_t *type_data, size_t type_data_len,
                             uint8_t *out, size_t out_cap)
{
    size_t total_len = EAP_HEADER_SIZE + 1 + type_data_len;
    if (total_len > 0xFFFF || total_len > out_cap) {
        return 0;
    }

    out[0] = code;
    out[1] = identifier;
    out[2] = (uint8_t)(total_len >> 8);
    out[3] = (uint8_t)(total_len);
    out[4] = type;
    if (type_data_len > 0) {
        memcpy(out + 5, type_data, type_data_len);
    }
    return total_len;
}

size_t eap_encode_request(uint8_t identifier, uint8_t type, const uint8_t *type_data,
                           size_t type_data_len, uint8_t *out, size_t out_cap)
{
    return encode_common(EAP_CODE_REQUEST, identifier, type, type_data, type_data_len, out, out_cap);
}

size_t eap_encode_response(uint8_t identifier, uint8_t type, const uint8_t *type_data,
                            size_t type_data_len, uint8_t *out, size_t out_cap)
{
    return encode_common(EAP_CODE_RESPONSE, identifier, type, type_data, type_data_len, out, out_cap);
}

size_t eap_encode_success(uint8_t identifier, uint8_t *out, size_t out_cap)
{
    if (out_cap < EAP_HEADER_SIZE) {
        return 0;
    }
    out[0] = EAP_CODE_SUCCESS;
    out[1] = identifier;
    out[2] = 0;
    out[3] = EAP_HEADER_SIZE;
    return EAP_HEADER_SIZE;
}

size_t eap_encode_failure(uint8_t identifier, uint8_t *out, size_t out_cap)
{
    if (out_cap < EAP_HEADER_SIZE) {
        return 0;
    }
    out[0] = EAP_CODE_FAILURE;
    out[1] = identifier;
    out[2] = 0;
    out[3] = EAP_HEADER_SIZE;
    return EAP_HEADER_SIZE;
}

int eap_decode(const uint8_t *buf, size_t len, eap_header_t *hdr,
               const uint8_t **type_data_out, size_t *type_data_len_out)
{
    if (len < EAP_HEADER_SIZE) {
        return -1;
    }

    hdr->code = buf[0];
    hdr->identifier = buf[1];
    hdr->length = (uint16_t)(((uint16_t)buf[2] << 8) | buf[3]);

    if (hdr->length != len) {
        return -1;
    }

    if (hdr->code == EAP_CODE_REQUEST || hdr->code == EAP_CODE_RESPONSE) {
        if (len < (size_t)EAP_HEADER_SIZE + 1) {
            return -1;
        }
        hdr->type = buf[4];
        size_t data_len = len - EAP_HEADER_SIZE - 1;
        *type_data_out = data_len > 0 ? buf + EAP_HEADER_SIZE + 1 : NULL;
        *type_data_len_out = data_len;
    } else if (hdr->code == EAP_CODE_SUCCESS || hdr->code == EAP_CODE_FAILURE) {
        if (len != EAP_HEADER_SIZE) {
            return -1;
        }
        hdr->type = 0;
        *type_data_out = NULL;
        *type_data_len_out = 0;
    } else {
        return -1;
    }

    return 0;
}
