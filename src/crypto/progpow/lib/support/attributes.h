/* ethash: C/C++ implementation of Ethash, the Ethereum Proof of Work algorithm.
 * Copyright 2018-2019 Pawel Bylica.
 * Licensed under the Apache License, Version 2.0.
 */

#pragma once
#ifndef CRYPTO_PROGPOW_ATTRIBUTES_H_
#define CRYPTO_PROGPOW_ATTRIBUTES_H_

/** inline */
#if defined(_MSC_VER) || defined(__STDC_VERSION__)
#define INLINE inline
#else
#define INLINE
#endif

/** [[always_inline]] */
#if defined(_MSC_VER)
#define ALWAYS_INLINE __forceinline
#elif defined(__has_attribute) && defined(__STDC_VERSION__)
#if __has_attribute(always_inline)
#define ALWAYS_INLINE __attribute__((always_inline))
#endif
#endif
#if !defined(ALWAYS_INLINE)
#define ALWAYS_INLINE
#endif

/** [[no_sanitize()]] */
#if defined(__clang__)
#define NO_SANITIZE(sanitizer) \
    __attribute__((no_sanitize(sanitizer)))
#else
#define NO_SANITIZE(sanitizer)
#endif
#endif // !CRYPTO_PROGPOW_ATTRIBUTES_H_