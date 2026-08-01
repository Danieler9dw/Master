/* Public-domain-style MD5 implementation per RFC 1321. */
#include "md5.h"
#include <string.h>

static const uint32_t K[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

static const uint32_t S[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

static uint32_t rotl(uint32_t x, uint32_t n)
{
    return (x << n) | (x >> (32 - n));
}

static void md5_process_block(md5_ctx_t *ctx, const uint8_t block[64])
{
    uint32_t M[16];
    for (int i = 0; i < 16; i++) {
        M[i] = (uint32_t)block[i * 4] |
               ((uint32_t)block[i * 4 + 1] << 8) |
               ((uint32_t)block[i * 4 + 2] << 16) |
               ((uint32_t)block[i * 4 + 3] << 24);
    }

    uint32_t A = ctx->state[0];
    uint32_t B = ctx->state[1];
    uint32_t C = ctx->state[2];
    uint32_t D = ctx->state[3];

    for (uint32_t i = 0; i < 64; i++) {
        uint32_t F;
        uint32_t g;
        if (i < 16) {
            F = (B & C) | (~B & D);
            g = i;
        } else if (i < 32) {
            F = (D & B) | (~D & C);
            g = (5 * i + 1) % 16;
        } else if (i < 48) {
            F = B ^ C ^ D;
            g = (3 * i + 5) % 16;
        } else {
            F = C ^ (B | ~D);
            g = (7 * i) % 16;
        }
        uint32_t tmp = D;
        D = C;
        C = B;
        F = A + F + K[i] + M[g];
        B = B + rotl(F, S[i]);
        A = tmp;
    }

    ctx->state[0] += A;
    ctx->state[1] += B;
    ctx->state[2] += C;
    ctx->state[3] += D;
}

void md5_init(md5_ctx_t *ctx)
{
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xefcdab89;
    ctx->state[2] = 0x98badcfe;
    ctx->state[3] = 0x10325476;
    ctx->bit_count = 0;
}

void md5_update(md5_ctx_t *ctx, const uint8_t *data, size_t len)
{
    size_t buffer_used = (size_t)((ctx->bit_count / 8) % 64);
    ctx->bit_count += (uint64_t)len * 8;

    size_t offset = 0;
    if (buffer_used > 0) {
        size_t needed = 64 - buffer_used;
        size_t take = len < needed ? len : needed;
        memcpy(ctx->buffer + buffer_used, data, take);
        offset += take;
        if (buffer_used + take == 64) {
            md5_process_block(ctx, ctx->buffer);
            buffer_used = 0;
        }
    }

    while (offset + 64 <= len) {
        md5_process_block(ctx, data + offset);
        offset += 64;
    }

    if (offset < len) {
        memcpy(ctx->buffer, data + offset, len - offset);
    }
}

void md5_final(md5_ctx_t *ctx, uint8_t digest[16])
{
    uint64_t bit_count = ctx->bit_count;
    size_t buffer_used = (size_t)((bit_count / 8) % 64);

    uint8_t pad = 0x80;
    md5_update(ctx, &pad, 1);

    uint8_t zero = 0x00;
    /* recompute buffer_used after the 0x80 byte was folded in by md5_update */
    buffer_used = (size_t)((ctx->bit_count / 8) % 64);
    size_t pad_zeros = (buffer_used <= 56) ? (56 - buffer_used) : (120 - buffer_used);
    for (size_t i = 0; i < pad_zeros; i++) {
        md5_update(ctx, &zero, 1);
    }

    uint8_t len_bytes[8];
    for (int i = 0; i < 8; i++) {
        len_bytes[i] = (uint8_t)((bit_count >> (8 * i)) & 0xff);
    }
    md5_update(ctx, len_bytes, 8);

    for (int i = 0; i < 4; i++) {
        digest[i * 4] = (uint8_t)(ctx->state[i] & 0xff);
        digest[i * 4 + 1] = (uint8_t)((ctx->state[i] >> 8) & 0xff);
        digest[i * 4 + 2] = (uint8_t)((ctx->state[i] >> 16) & 0xff);
        digest[i * 4 + 3] = (uint8_t)((ctx->state[i] >> 24) & 0xff);
    }
}

void md5_digest(const uint8_t *data, size_t len, uint8_t digest[16])
{
    md5_ctx_t ctx;
    md5_init(&ctx);
    md5_update(&ctx, data, len);
    md5_final(&ctx, digest);
}
