/**
 * \file oht_mbedtls_config.h
 *
 * \brief Minimal Mbed TLS 3.6 configuration for OpenHashTab
 *
 * Only the hash modules exposed by OpenHashTab are enabled. Nothing else from
 * Mbed TLS (TLS, X.509, PK, ciphers, PSA, RNG, ...) is built or used.
 *
 * MD4 is no longer part of Mbed TLS 3.x and is provided by Algorithms/md4.
 *
 * Note: this file must not be named mbedtls_config.h, since build_info.h
 * includes MBEDTLS_CONFIG_FILE with quotes, which would pick up the default
 * include/mbedtls/mbedtls_config.h sitting next to it instead.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef OHT_MBEDTLS_CONFIG_H
#define OHT_MBEDTLS_CONFIG_H

#if defined(_MSC_VER) && !defined(_CRT_SECURE_NO_DEPRECATE)
#define _CRT_SECURE_NO_DEPRECATE 1
#endif

#define MBEDTLS_MD5_C
#define MBEDTLS_RIPEMD160_C
#define MBEDTLS_SHA1_C
#define MBEDTLS_SHA224_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA384_C
#define MBEDTLS_SHA512_C

#endif /* OHT_MBEDTLS_CONFIG_H */
