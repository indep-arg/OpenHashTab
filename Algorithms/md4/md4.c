/*
 *  RFC 1186/1320 compliant MD4 implementation
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 *
 *  Taken from Mbed TLS 2.28.10 (library/md4.c). See md4.h for the changes.
 */
/*
 *  The MD4 algorithm was designed by Ron Rivest in 1990.
 *
 *  http://www.ietf.org/rfc/rfc1186.txt
 *  http://www.ietf.org/rfc/rfc1320.txt
 */

#include "md4.h"

#include <string.h>

#define MBEDTLS_GET_UINT32_LE(data, offset)                   \
    ((uint32_t) (data)[(offset)]                              \
     | ((uint32_t) (data)[(offset) + 1] << 8)                 \
     | ((uint32_t) (data)[(offset) + 2] << 16)                \
     | ((uint32_t) (data)[(offset) + 3] << 24))

#define MBEDTLS_PUT_UINT32_LE(n, data, offset)                \
    do {                                                      \
        (data)[(offset)]     = (unsigned char) ((n));         \
        (data)[(offset) + 1] = (unsigned char) ((n) >> 8);    \
        (data)[(offset) + 2] = (unsigned char) ((n) >> 16);   \
        (data)[(offset) + 3] = (unsigned char) ((n) >> 24);   \
    } while (0)

static void mbedtls_platform_zeroize(void *buf, size_t len)
{
    volatile unsigned char *p = (volatile unsigned char *) buf;
    while (len--) {
        *p++ = 0;
    }
}

void mbedtls_md4_init(mbedtls_md4_context *ctx)
{
    memset(ctx, 0, sizeof(mbedtls_md4_context));
}

void mbedtls_md4_free(mbedtls_md4_context *ctx)
{
    if (ctx == NULL) {
        return;
    }

    mbedtls_platform_zeroize(ctx, sizeof(mbedtls_md4_context));
}

void mbedtls_md4_clone(mbedtls_md4_context *dst,
                       const mbedtls_md4_context *src)
{
    *dst = *src;
}

/*
 * MD4 context setup
 */
int mbedtls_md4_starts(mbedtls_md4_context *ctx)
{
    ctx->total[0] = 0;
    ctx->total[1] = 0;

    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;

    return 0;
}

static int mbedtls_internal_md4_process(mbedtls_md4_context *ctx,
                                        const unsigned char data[64])
{
    struct {
        uint32_t X[16], A, B, C, D;
    } local;

    local.X[0] = MBEDTLS_GET_UINT32_LE(data,  0);
    local.X[1] = MBEDTLS_GET_UINT32_LE(data,  4);
    local.X[2] = MBEDTLS_GET_UINT32_LE(data,  8);
    local.X[3] = MBEDTLS_GET_UINT32_LE(data, 12);
    local.X[4] = MBEDTLS_GET_UINT32_LE(data, 16);
    local.X[5] = MBEDTLS_GET_UINT32_LE(data, 20);
    local.X[6] = MBEDTLS_GET_UINT32_LE(data, 24);
    local.X[7] = MBEDTLS_GET_UINT32_LE(data, 28);
    local.X[8] = MBEDTLS_GET_UINT32_LE(data, 32);
    local.X[9] = MBEDTLS_GET_UINT32_LE(data, 36);
    local.X[10] = MBEDTLS_GET_UINT32_LE(data, 40);
    local.X[11] = MBEDTLS_GET_UINT32_LE(data, 44);
    local.X[12] = MBEDTLS_GET_UINT32_LE(data, 48);
    local.X[13] = MBEDTLS_GET_UINT32_LE(data, 52);
    local.X[14] = MBEDTLS_GET_UINT32_LE(data, 56);
    local.X[15] = MBEDTLS_GET_UINT32_LE(data, 60);

#define S(x, n) (((x) << (n)) | (((x) & 0xFFFFFFFF) >> (32 - (n))))

    local.A = ctx->state[0];
    local.B = ctx->state[1];
    local.C = ctx->state[2];
    local.D = ctx->state[3];

#define F(x, y, z) (((x) & (y)) | ((~(x)) & (z)))
#define P(a, b, c, d, x, s)                           \
    do                                           \
    {                                            \
        (a) += F((b), (c), (d)) + (x);             \
        (a) = S((a), (s));                        \
    } while (0)

    P(local.A, local.B, local.C, local.D, local.X[0],  3);
    P(local.D, local.A, local.B, local.C, local.X[1],  7);
    P(local.C, local.D, local.A, local.B, local.X[2], 11);
    P(local.B, local.C, local.D, local.A, local.X[3], 19);
    P(local.A, local.B, local.C, local.D, local.X[4],  3);
    P(local.D, local.A, local.B, local.C, local.X[5],  7);
    P(local.C, local.D, local.A, local.B, local.X[6], 11);
    P(local.B, local.C, local.D, local.A, local.X[7], 19);
    P(local.A, local.B, local.C, local.D, local.X[8],  3);
    P(local.D, local.A, local.B, local.C, local.X[9],  7);
    P(local.C, local.D, local.A, local.B, local.X[10], 11);
    P(local.B, local.C, local.D, local.A, local.X[11], 19);
    P(local.A, local.B, local.C, local.D, local.X[12],  3);
    P(local.D, local.A, local.B, local.C, local.X[13],  7);
    P(local.C, local.D, local.A, local.B, local.X[14], 11);
    P(local.B, local.C, local.D, local.A, local.X[15], 19);

#undef P
#undef F

#define F(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define P(a, b, c, d, x, s)                          \
    do                                          \
    {                                           \
        (a) += F((b), (c), (d)) + (x) + 0x5A827999;       \
        (a) = S((a), (s));                               \
    } while (0)

    P(local.A, local.B, local.C, local.D, local.X[0],  3);
    P(local.D, local.A, local.B, local.C, local.X[4],  5);
    P(local.C, local.D, local.A, local.B, local.X[8],  9);
    P(local.B, local.C, local.D, local.A, local.X[12], 13);
    P(local.A, local.B, local.C, local.D, local.X[1],  3);
    P(local.D, local.A, local.B, local.C, local.X[5],  5);
    P(local.C, local.D, local.A, local.B, local.X[9],  9);
    P(local.B, local.C, local.D, local.A, local.X[13], 13);
    P(local.A, local.B, local.C, local.D, local.X[2],  3);
    P(local.D, local.A, local.B, local.C, local.X[6],  5);
    P(local.C, local.D, local.A, local.B, local.X[10],  9);
    P(local.B, local.C, local.D, local.A, local.X[14], 13);
    P(local.A, local.B, local.C, local.D, local.X[3],  3);
    P(local.D, local.A, local.B, local.C, local.X[7],  5);
    P(local.C, local.D, local.A, local.B, local.X[11],  9);
    P(local.B, local.C, local.D, local.A, local.X[15], 13);

#undef P
#undef F

#define F(x, y, z) ((x) ^ (y) ^ (z))
#define P(a, b, c, d, x, s)                                  \
    do                                                  \
    {                                                   \
        (a) += F((b), (c), (d)) + (x) + 0x6ED9EBA1;       \
        (a) = S((a), (s));                               \
    } while (0)

    P(local.A, local.B, local.C, local.D, local.X[0],  3);
    P(local.D, local.A, local.B, local.C, local.X[8],  9);
    P(local.C, local.D, local.A, local.B, local.X[4], 11);
    P(local.B, local.C, local.D, local.A, local.X[12], 15);
    P(local.A, local.B, local.C, local.D, local.X[2],  3);
    P(local.D, local.A, local.B, local.C, local.X[10],  9);
    P(local.C, local.D, local.A, local.B, local.X[6], 11);
    P(local.B, local.C, local.D, local.A, local.X[14], 15);
    P(local.A, local.B, local.C, local.D, local.X[1],  3);
    P(local.D, local.A, local.B, local.C, local.X[9],  9);
    P(local.C, local.D, local.A, local.B, local.X[5], 11);
    P(local.B, local.C, local.D, local.A, local.X[13], 15);
    P(local.A, local.B, local.C, local.D, local.X[3],  3);
    P(local.D, local.A, local.B, local.C, local.X[11],  9);
    P(local.C, local.D, local.A, local.B, local.X[7], 11);
    P(local.B, local.C, local.D, local.A, local.X[15], 15);

#undef F
#undef P

    ctx->state[0] += local.A;
    ctx->state[1] += local.B;
    ctx->state[2] += local.C;
    ctx->state[3] += local.D;

    /* Zeroise variables to clear sensitive data from memory. */
    mbedtls_platform_zeroize(&local, sizeof(local));

    return 0;
}

/*
 * MD4 process buffer
 */
int mbedtls_md4_update(mbedtls_md4_context *ctx,
                       const unsigned char *input,
                       size_t ilen)
{
    int ret = -1;
    size_t fill;
    uint32_t left;

    if (ilen == 0) {
        return 0;
    }

    left = ctx->total[0] & 0x3F;
    fill = 64 - left;

    ctx->total[0] += (uint32_t) ilen;
    ctx->total[0] &= 0xFFFFFFFF;

    if (ctx->total[0] < (uint32_t) ilen) {
        ctx->total[1]++;
    }

    if (left && ilen >= fill) {
        memcpy((void *) (ctx->buffer + left),
               (void *) input, fill);

        if ((ret = mbedtls_internal_md4_process(ctx, ctx->buffer)) != 0) {
            return ret;
        }

        input += fill;
        ilen  -= fill;
        left = 0;
    }

    while (ilen >= 64) {
        if ((ret = mbedtls_internal_md4_process(ctx, input)) != 0) {
            return ret;
        }

        input += 64;
        ilen  -= 64;
    }

    if (ilen > 0) {
        memcpy((void *) (ctx->buffer + left),
               (void *) input, ilen);
    }

    return 0;
}

static const unsigned char md4_padding[64] =
{
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/*
 * MD4 final digest
 */
int mbedtls_md4_finish(mbedtls_md4_context *ctx,
                       unsigned char output[16])
{
    int ret = -1;
    uint32_t last, padn;
    uint32_t high, low;
    unsigned char msglen[8];

    high = (ctx->total[0] >> 29)
           | (ctx->total[1] <<  3);
    low  = (ctx->total[0] <<  3);

    MBEDTLS_PUT_UINT32_LE(low,  msglen, 0);
    MBEDTLS_PUT_UINT32_LE(high, msglen, 4);

    last = ctx->total[0] & 0x3F;
    padn = (last < 56) ? (56 - last) : (120 - last);

    ret = mbedtls_md4_update(ctx, (unsigned char *) md4_padding, padn);
    if (ret != 0) {
        return ret;
    }

    if ((ret = mbedtls_md4_update(ctx, msglen, 8)) != 0) {
        return ret;
    }

    MBEDTLS_PUT_UINT32_LE(ctx->state[0], output,  0);
    MBEDTLS_PUT_UINT32_LE(ctx->state[1], output,  4);
    MBEDTLS_PUT_UINT32_LE(ctx->state[2], output,  8);
    MBEDTLS_PUT_UINT32_LE(ctx->state[3], output, 12);

    return 0;
}
