#include "eap_attr.h"

#include <stdio.h>
#include <string.h>

static int test_append_and_iterate_roundtrip(void)
{
    uint8_t buf[128];
    size_t offset = 0;

    const uint8_t val_a[2] = {0x11, 0x22};       /* pads to 4 bytes total value+hdr -> 4 */
    const uint8_t val_b[5] = {1, 2, 3, 4, 5};    /* not a multiple of 4, needs padding */

    if (eap_attr_append(buf, sizeof(buf), &offset, 10, val_a, sizeof(val_a)) != 0 ||
        eap_attr_append(buf, sizeof(buf), &offset, 200, val_b, sizeof(val_b)) != 0 ||
        eap_attr_append(buf, sizeof(buf), &offset, 5, NULL, 0) != 0) {
        fprintf(stderr, "FAIL: eap_attr_append failed unexpectedly\n");
        return -1;
    }

    eap_attr_iter_t iter;
    eap_attr_iter_init(&iter, buf, offset);

    eap_attr_t attr;
    int rc = eap_attr_iter_next(&iter, &attr);
    if (rc != 1 || attr.type != 10 || attr.value_len != 2 || memcmp(attr.value, val_a, 2) != 0) {
        fprintf(stderr, "FAIL: first attribute mismatch (rc=%d)\n", rc);
        return -1;
    }

    rc = eap_attr_iter_next(&iter, &attr);
    /* value_len includes zero padding: 2(hdr)+5(value) = 7 -> rounds to 8 -> value_len = 6 */
    if (rc != 1 || attr.type != 200 || attr.value_len != 6 || memcmp(attr.value, val_b, 5) != 0 ||
        attr.value[5] != 0) {
        fprintf(stderr, "FAIL: second attribute mismatch (rc=%d)\n", rc);
        return -1;
    }
    if (!eap_attr_is_skippable(attr.type)) {
        fprintf(stderr, "FAIL: type 200 should be skippable\n");
        return -1;
    }

    rc = eap_attr_iter_next(&iter, &attr);
    if (rc != 1 || attr.type != 5 || attr.value_len != 2) {
        fprintf(stderr, "FAIL: third attribute mismatch (rc=%d)\n", rc);
        return -1;
    }
    if (eap_attr_is_skippable(attr.type)) {
        fprintf(stderr, "FAIL: type 5 should not be skippable\n");
        return -1;
    }

    rc = eap_attr_iter_next(&iter, &attr);
    if (rc != 0) {
        fprintf(stderr, "FAIL: expected no more attributes, got rc=%d\n", rc);
        return -1;
    }

    return 0;
}

static int test_iter_rejects_malformed(void)
{
    eap_attr_iter_t iter;
    eap_attr_t attr;

    /* Truncated header: only one byte present. */
    uint8_t truncated_header[1] = {5};
    eap_attr_iter_init(&iter, truncated_header, sizeof(truncated_header));
    if (eap_attr_iter_next(&iter, &attr) != -1) {
        fprintf(stderr, "FAIL: accepted a truncated attribute header\n");
        return -1;
    }

    /* Zero Length. */
    uint8_t zero_length[4] = {5, 0, 0, 0};
    eap_attr_iter_init(&iter, zero_length, sizeof(zero_length));
    if (eap_attr_iter_next(&iter, &attr) != -1) {
        fprintf(stderr, "FAIL: accepted a zero-Length attribute\n");
        return -1;
    }

    /* Length says 2 words (8 bytes) but only 4 bytes are present. */
    uint8_t truncated_value[4] = {5, 2, 0, 0};
    eap_attr_iter_init(&iter, truncated_value, sizeof(truncated_value));
    if (eap_attr_iter_next(&iter, &attr) != -1) {
        fprintf(stderr, "FAIL: accepted a truncated attribute value\n");
        return -1;
    }

    return 0;
}

static int test_append_rejects_undersized_buffer(void)
{
    uint8_t tiny[3];
    size_t offset = 0;
    uint8_t value[4] = {0};
    if (eap_attr_append(tiny, sizeof(tiny), &offset, 1, value, sizeof(value)) == 0) {
        fprintf(stderr, "FAIL: eap_attr_append wrote past an undersized buffer\n");
        return -1;
    }
    if (offset != 0) {
        fprintf(stderr, "FAIL: eap_attr_append advanced offset despite failing\n");
        return -1;
    }
    return 0;
}

int main(void)
{
    int failures = 0;
    failures += test_append_and_iterate_roundtrip() != 0;
    failures += test_iter_rejects_malformed() != 0;
    failures += test_append_rejects_undersized_buffer() != 0;

    if (failures) {
        fprintf(stderr, "%d test(s) failed\n", failures);
        return 1;
    }
    printf("all eap_attr tests passed\n");
    return 0;
}
