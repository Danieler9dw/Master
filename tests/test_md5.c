/* Known-answer tests from RFC 1321 Appendix A.5. */
#include "md5.h"

#include <stdio.h>
#include <string.h>

static int check(const char *input, const char *expected_hex)
{
    uint8_t digest[16];
    md5_digest((const uint8_t *)input, strlen(input), digest);

    char hex[33];
    for (int i = 0; i < 16; i++) {
        sprintf(hex + i * 2, "%02x", digest[i]);
    }
    hex[32] = '\0';

    if (strcmp(hex, expected_hex) != 0) {
        fprintf(stderr, "FAIL: md5(\"%s\") = %s, expected %s\n", input, hex, expected_hex);
        return -1;
    }
    return 0;
}

int main(void)
{
    int failures = 0;
    failures += check("", "d41d8cd98f00b204e9800998ecf8427e") != 0;
    failures += check("a", "0cc175b9c0f1b6a831c399e269772661") != 0;
    failures += check("abc", "900150983cd24fb0d6963f7d28e17f72") != 0;
    failures += check("message digest", "f96b697d7cb7938d525a2f31aaf161d0") != 0;
    failures += check("abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b") != 0;
    failures += check("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                       "d174ab98d277d9f5a5611c2c9f419d9f") != 0;
    /* 80 bytes: exercises the multi-block path. */
    failures += check("12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                       "57edf4a22be3c955ac49da2e2107b67a") != 0;

    if (failures) {
        fprintf(stderr, "%d test(s) failed\n", failures);
        return 1;
    }
    printf("all md5 tests passed\n");
    return 0;
}
