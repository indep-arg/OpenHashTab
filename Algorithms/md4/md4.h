/*
 *  RFC 1186/1320 compliant MD4 implementation
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 *
 *  Taken from Mbed TLS 2.28.10 (library/md4.c, include/mbedtls/md4.h), since
 *  Mbed TLS 3.0 and later no longer provide MD4. Stripped of the Mbed TLS
 *  configuration, deprecated and self-test code, and adapted to the 3.x style
 *  API (no _ret suffixes) used for the other hashes.
 */
#ifndef OHT_MD4_H
#define OHT_MD4_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mbedtls_md4_context {
    uint32_t total[2];          /*!< number of bytes processed  */
    uint32_t state[4];          /*!< intermediate digest state  */
    unsigned char buffer[64];   /*!< data block being processed */
} mbedtls_md4_context;

void mbedtls_md4_init(mbedtls_md4_context *ctx);
void mbedtls_md4_free(mbedtls_md4_context *ctx);
void mbedtls_md4_clone(mbedtls_md4_context *dst, const mbedtls_md4_context *src);
int mbedtls_md4_starts(mbedtls_md4_context *ctx);
int mbedtls_md4_update(mbedtls_md4_context *ctx, const unsigned char *input, size_t ilen);
int mbedtls_md4_finish(mbedtls_md4_context *ctx, unsigned char output[16]);

#ifdef __cplusplus
}
#endif

#endif /* OHT_MD4_H */
