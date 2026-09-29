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
