/* The Type/Length/Value attribute ("AT_*") format shared by the EAP-SIM,
 * EAP-AKA, and EAP-AKA' methods (RFC 4186 section 8.1 and the RFCs that
 * reuse it):
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | Attribute Type|    Length     |          Value...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Length is the length of the whole attribute (Type + Length + Value), in
 * multiples of 4 bytes; Value is zero-padded up to that multiple. By
 * convention (shared across the same set of RFCs) an Attribute Type in
 * [0, 127] must be understood or the message rejected, while one in
 * [128, 255] may be silently skipped if unrecognized.
 *
 * This module only implements that generic container -- it does not know
 * any method-specific attribute type numbers (AT_RAND, AT_MAC, ...) or
 * internal sub-fields. See CLAUDE.md for why those aren't implemented yet.
 */
#ifndef TAC_EAP_ATTR_H
#define TAC_EAP_ATTR_H

#include <stddef.h>
#include <stdint.h>

static inline int eap_attr_is_skippable(uint8_t type)
{
    return type >= 128;
}

typedef struct {
    uint8_t type;
    const uint8_t *value; /* points into the buffer passed to eap_attr_iter_init */
    size_t value_len;     /* may include this attribute's own zero padding */
} eap_attr_t;

typedef struct {
    const uint8_t *buf;
    size_t len;
    size_t offset;
} eap_attr_iter_t;

void eap_attr_iter_init(eap_attr_iter_t *iter, const uint8_t *buf, size_t len);

/* Returns 1 and fills *out with the next attribute, 0 if there are no more
 * (offset == len exactly), or -1 if the buffer is malformed (a truncated
 * attribute header/value, or a zero Length). */
int eap_attr_iter_next(eap_attr_iter_t *iter, eap_attr_t *out);

/* Appends one attribute (type + value, zero-padded to a 4-byte multiple)
 * to out at *out_offset, advancing it. Returns 0 on success, -1 if
 * out_cap is too small or the padded attribute would exceed 255*4 bytes
 * (the largest Length can express). */
int eap_attr_append(uint8_t *out, size_t out_cap, size_t *out_offset, uint8_t type,
                     const uint8_t *value, size_t value_len);

#endif
