#include "eap.h"

#include <stdio.h>
#include <string.h>

static int test_request_roundtrip(void)
{
    const uint8_t type_data[] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee};
    uint8_t buf[64];

    size_t n = eap_encode_request(7, 50, type_data, sizeof(type_data), buf, sizeof(buf));
    if (n != EAP_HEADER_SIZE + 1 + sizeof(type_data)) {
        fprintf(stderr, "FAIL: eap_encode_request returned unexpected length %zu\n", n);
        return -1;
    }

    eap_header_t hdr;
    const uint8_t *data;
    size_t data_len;
    if (eap_decode(buf, n, &hdr, &data, &data_len) != 0) {
        fprintf(stderr, "FAIL: eap_decode rejected a valid Request packet\n");
        return -1;
    }
    if (hdr.code != EAP_CODE_REQUEST || hdr.identifier != 7 || hdr.type != 50) {
        fprintf(stderr, "FAIL: decoded Request header mismatch\n");
        return -1;
    }
    if (data_len != sizeof(type_data) || memcmp(data, type_data, data_len) != 0) {
        fprintf(stderr, "FAIL: decoded Request type-data mismatch\n");
        return -1;
    }
    return 0;
}

static int test_response_roundtrip_empty_data(void)
{
    uint8_t buf[16];
    size_t n = eap_encode_response(3, 1, NULL, 0, buf, sizeof(buf));
    if (n != EAP_HEADER_SIZE + 1) {
        fprintf(stderr, "FAIL: eap_encode_response (empty data) returned %zu\n", n);
        return -1;
    }

    eap_header_t hdr;
    const uint8_t *data;
    size_t data_len;
    if (eap_decode(buf, n, &hdr, &data, &data_len) != 0) {
        fprintf(stderr, "FAIL: eap_decode rejected a valid empty-data Response\n");
        return -1;
    }
    if (hdr.code != EAP_CODE_RESPONSE || data_len != 0 || data != NULL) {
        fprintf(stderr, "FAIL: decoded empty-data Response mismatch\n");
        return -1;
    }
    return 0;
}

static int test_success_failure_roundtrip(void)
{
    uint8_t buf[EAP_HEADER_SIZE];

    if (eap_encode_success(42, buf, sizeof(buf)) != EAP_HEADER_SIZE) {
        fprintf(stderr, "FAIL: eap_encode_success returned wrong length\n");
        return -1;
    }
    eap_header_t hdr;
    const uint8_t *data;
    size_t data_len;
    if (eap_decode(buf, sizeof(buf), &hdr, &data, &data_len) != 0 ||
        hdr.code != EAP_CODE_SUCCESS || hdr.identifier != 42 || data != NULL || data_len != 0) {
        fprintf(stderr, "FAIL: Success roundtrip mismatch\n");
        return -1;
    }

    if (eap_encode_failure(99, buf, sizeof(buf)) != EAP_HEADER_SIZE) {
        fprintf(stderr, "FAIL: eap_encode_failure returned wrong length\n");
        return -1;
    }
    if (eap_decode(buf, sizeof(buf), &hdr, &data, &data_len) != 0 ||
        hdr.code != EAP_CODE_FAILURE || hdr.identifier != 99) {
        fprintf(stderr, "FAIL: Failure roundtrip mismatch\n");
        return -1;
    }
    return 0;
}

static int test_decode_rejects_malformed(void)
{
    eap_header_t hdr;
    const uint8_t *data;
    size_t data_len;

    uint8_t too_short[3] = {1, 1, 0};
    if (eap_decode(too_short, sizeof(too_short), &hdr, &data, &data_len) == 0) {
        fprintf(stderr, "FAIL: eap_decode accepted a buffer shorter than the header\n");
        return -1;
    }

    /* Length field says 10 but the buffer is only 5 bytes. */
    uint8_t bad_length[5] = {EAP_CODE_REQUEST, 1, 0, 10, 4};
    if (eap_decode(bad_length, sizeof(bad_length), &hdr, &data, &data_len) == 0) {
        fprintf(stderr, "FAIL: eap_decode accepted a Length mismatch\n");
        return -1;
    }

    /* Request with no room for the Type byte, but Length matches len. */
    uint8_t no_type[4] = {EAP_CODE_REQUEST, 1, 0, 4};
    if (eap_decode(no_type, sizeof(no_type), &hdr, &data, &data_len) == 0) {
        fprintf(stderr, "FAIL: eap_decode accepted a Request with no Type byte\n");
        return -1;
    }

    /* Success packet with a trailing byte beyond EAP_HEADER_SIZE. */
    uint8_t bad_success[5] = {EAP_CODE_SUCCESS, 1, 0, 5, 0};
    if (eap_decode(bad_success, sizeof(bad_success), &hdr, &data, &data_len) == 0) {
        fprintf(stderr, "FAIL: eap_decode accepted an oversized Success packet\n");
        return -1;
    }

    return 0;
}

static int test_encode_rejects_undersized_buffer(void)
{
    uint8_t type_data[10] = {0};
    uint8_t tiny[3];
    if (eap_encode_request(1, 1, type_data, sizeof(type_data), tiny, sizeof(tiny)) != 0) {
        fprintf(stderr, "FAIL: eap_encode_request wrote past an undersized buffer\n");
        return -1;
    }
    return 0;
}

int main(void)
{
    int failures = 0;
    failures += test_request_roundtrip() != 0;
    failures += test_response_roundtrip_empty_data() != 0;
    failures += test_success_failure_roundtrip() != 0;
    failures += test_decode_rejects_malformed() != 0;
    failures += test_encode_rejects_undersized_buffer() != 0;

    if (failures) {
        fprintf(stderr, "%d test(s) failed\n", failures);
        return 1;
    }
    printf("all eap tests passed\n");
    return 0;
}
