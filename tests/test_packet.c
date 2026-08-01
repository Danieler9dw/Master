#include "packet.h"

#include <stdio.h>
#include <string.h>

static int test_header_roundtrip(void)
{
    tac_header_t hdr = {
        .version = (uint8_t)((TAC_PLUS_MAJOR_VER << 4) | TAC_PLUS_MINOR_VER_DEFAULT),
        .type = TAC_PLUS_AUTHEN,
        .seq_no = 1,
        .flags = TAC_PLUS_SINGLE_CONNECT_FLAG,
        .session_id = 0xdeadbeef,
        .length = 42,
    };

    uint8_t buf[TAC_HEADER_SIZE];
    tac_header_encode(&hdr, buf);

    tac_header_t decoded;
    if (tac_header_decode(buf, &decoded) != 0) {
        fprintf(stderr, "FAIL: header_decode returned error on a valid header\n");
        return -1;
    }
    if (memcmp(&hdr, &decoded, sizeof(hdr)) != 0) {
        fprintf(stderr, "FAIL: header roundtrip mismatch\n");
        return -1;
    }
    return 0;
}

static int test_header_rejects_bad_type(void)
{
    tac_header_t hdr = {
        .version = TAC_PLUS_MAJOR_VER << 4,
        .type = 0x99, /* not a valid AUTHEN/AUTHOR/ACCT type */
        .seq_no = 1,
        .flags = 0,
        .session_id = 1,
        .length = 0,
    };

    uint8_t buf[TAC_HEADER_SIZE];
    tac_header_encode(&hdr, buf);

    tac_header_t decoded;
    if (tac_header_decode(buf, &decoded) == 0) {
        fprintf(stderr, "FAIL: header_decode accepted an invalid packet type\n");
        return -1;
    }
    return 0;
}

static int test_header_rejects_oversized_length(void)
{
    tac_header_t hdr = {
        .version = TAC_PLUS_MAJOR_VER << 4,
        .type = TAC_PLUS_AUTHEN,
        .seq_no = 1,
        .flags = 0,
        .session_id = 1,
        .length = TAC_MAX_BODY_SIZE + 1,
    };

    uint8_t buf[TAC_HEADER_SIZE];
    tac_header_encode(&hdr, buf);

    tac_header_t decoded;
    if (tac_header_decode(buf, &decoded) == 0) {
        fprintf(stderr, "FAIL: header_decode accepted a length above TAC_MAX_BODY_SIZE\n");
        return -1;
    }
    return 0;
}

static int test_crypt_roundtrip(void)
{
    tac_header_t hdr = {
        .version = TAC_PLUS_MAJOR_VER << 4,
        .type = TAC_PLUS_AUTHEN,
        .seq_no = 1,
        .flags = 0,
        .session_id = 123456,
        .length = 0,
    };

    const char *key = "supersecretkey";
    uint8_t plaintext[100];
    for (size_t i = 0; i < sizeof(plaintext); i++) {
        plaintext[i] = (uint8_t)i;
    }

    uint8_t buf[sizeof(plaintext)];
    memcpy(buf, plaintext, sizeof(buf));

    tac_crypt(&hdr, key, buf, sizeof(buf));
    if (memcmp(buf, plaintext, sizeof(buf)) == 0) {
        fprintf(stderr, "FAIL: tac_crypt did not change the data\n");
        return -1;
    }

    tac_crypt(&hdr, key, buf, sizeof(buf)); /* symmetric: apply again to decrypt */
    if (memcmp(buf, plaintext, sizeof(buf)) != 0) {
        fprintf(stderr, "FAIL: tac_crypt roundtrip did not recover the plaintext\n");
        return -1;
    }
    return 0;
}

int main(void)
{
    int failures = 0;
    failures += test_header_roundtrip() != 0;
    failures += test_header_rejects_bad_type() != 0;
    failures += test_header_rejects_oversized_length() != 0;
    failures += test_crypt_roundtrip() != 0;

    if (failures) {
        fprintf(stderr, "%d test(s) failed\n", failures);
        return 1;
    }
    printf("all packet tests passed\n");
    return 0;
}
