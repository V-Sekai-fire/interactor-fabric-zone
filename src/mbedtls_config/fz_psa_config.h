// SPDX-FileCopyrightText: 2026 K. S. Ernest (iFire) Lee
// SPDX-License-Identifier: MIT
// The crypto configuration for the guests and their native tests: upstream's defaults, minus stored
// keys, threads and the built-in entropy, plus the entropy callback in src/ca/fz_entropy.cpp. File
// parsing stays compiled because picoquic's mbedTLS glue references it; nothing calls it at runtime.
#pragma once
#include <psa/crypto_config.h>


#undef MBEDTLS_PSA_CRYPTO_STORAGE_C
#undef MBEDTLS_PSA_ITS_FILE_C
#undef MBEDTLS_PSA_BUILTIN_GET_ENTROPY
#define MBEDTLS_PSA_DRIVER_GET_ENTROPY
#undef MBEDTLS_AESNI_C
#undef MBEDTLS_AESCE_C
#undef MBEDTLS_HAVE_ASM

// In the sandbox, glibc's time() answers a small count rather than the wall clock (28 under the
// pinned double editor), while clock_gettime(CLOCK_REALTIME) answers the host's. mbedTLS checks a
// peer certificate's validity against mbedtls_time(), so the guests read the wall clock through
// clock_gettime in src/ca/fz_entropy.cpp; with time() every certificate is not yet valid.
#if defined(__riscv)
#include <time.h>
#ifdef __cplusplus
extern "C"
#endif
time_t fz_wall_time(time_t *r_time);
#define MBEDTLS_PLATFORM_TIME_MACRO fz_wall_time
#endif
