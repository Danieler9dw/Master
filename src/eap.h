/* Generic EAP packet framing per RFC 3748 section 4.
 *
 * This is transport-agnostic: it only encodes/decodes the Code,
 * Identifier, Length, and (for Request/Response) Type fields around a
 * caller-supplied Type-Data payload. It knows nothing about any specific
 * EAP method (MD5-Challenge, AKA, AKA', ...).
 */
#ifndef TAC_EAP_H
#define TAC_EAP_H

#include <stddef.h>
#include <stdint.h>

#define EAP_CODE_REQUEST 1
#define EAP_CODE_RESPONSE 2
#define EAP_CODE_SUCCESS 3
#define EAP_CODE_FAILURE 4

/* Code + Identifier + Length; Success/Failure packets are exactly this
 * long, Request/Response packets have one more Type byte plus Type-Data. */
#define EAP_HEADER_SIZE 4

typedef struct {
    uint8_t code;
    uint8_t identifier;
    uint16_t length;
    /* Only meaningful when code is EAP_CODE_REQUEST or EAP_CODE_RESPONSE. */
    uint8_t type;
} eap_header_t;

/* Encodes a Request or Response packet (header + type + type_data) into
 * out. Returns the number of bytes written (EAP_HEADER_SIZE + 1 +
 * type_data_len), or 0 if out_cap is too small or type_data_len would
 * overflow the 16-bit Length field. */
size_t eap_encode_request(uint8_t identifier, uint8_t type, const uint8_t *type_data,
                           size_t type_data_len, uint8_t *out, size_t out_cap);
size_t eap_encode_response(uint8_t identifier, uint8_t type, const uint8_t *type_data,
                            size_t type_data_len, uint8_t *out, size_t out_cap);

/* Encodes a Success or Failure packet (header only). Returns EAP_HEADER_SIZE,
 * or 0 if out_cap is too small. */
size_t eap_encode_success(uint8_t identifier, uint8_t *out, size_t out_cap);
size_t eap_encode_failure(uint8_t identifier, uint8_t *out, size_t out_cap);

/* Decodes a full EAP packet already in memory. hdr->type is only valid
 * when hdr->code is EAP_CODE_REQUEST or EAP_CODE_RESPONSE. On success,
 * *type_data_out points into buf (no copy) and *type_data_len_out is set;
 * both are set to NULL/0 for Success/Failure packets.
 *
 * Returns 0 on success, -1 if buf is malformed: shorter than
 * EAP_HEADER_SIZE, shorter than a Request/Response needs for its Type
 * byte, or the embedded Length field doesn't equal len exactly. */
int eap_decode(const uint8_t *buf, size_t len, eap_header_t *hdr,
               const uint8_t **type_data_out, size_t *type_data_len_out);

#endif
