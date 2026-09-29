// SPDX-FileCopyrightText: 2026 K. S. Ernest (iFire) Lee
// SPDX-License-Identifier: MIT
// The session CA and the keys its certificates name, as a C API: the guest (guest/ca) and the Lean
// tests (tests/ffi) both call exactly these functions.
#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
	FZ_ENTROPY_NONE = 0,
	FZ_ENTROPY_OS = 1,
	FZ_ENTROPY_HOST = 2,
};

enum {
	FZ_ERR_NAME = -100,
	FZ_ERR_TTL = -101,
	FZ_ERR_CSR = -102,
	FZ_ERR_CSR_SIGNATURE = -103,
	FZ_ERR_BUFFER = -104,
	FZ_ERR_CRYPTO = -105,
	FZ_ERR_ENTROPY = -106,
};

enum {
	FZ_BAD_CHAIN = 1,
	FZ_EXPIRED = 2,
	FZ_NOT_YET_VALID = 4,
	FZ_BAD_NAME = 8,
	FZ_BAD_PARSE = 16,
};

#define FZ_MAX_SECONDS 3600
#define FZ_NAME_SUFFIX ".zone.fabric.internal"

typedef struct fz_ca fz_ca;
typedef struct fz_key fz_key;

// Entropy: the OS source (getrandom) first; host-fed bytes when it fails or when forced.
int fz_entropy_probe(unsigned char *r_out32);
int fz_entropy_source(void);
void fz_entropy_force_host(int p_on);
int fz_entropy_feed(const unsigned char *p_bytes, size_t p_count);
size_t fz_entropy_pool_left(void);

int fz_crypto_init(void);

int fz_name_allowed(const char *p_name);

fz_ca *fz_ca_new(int64_t p_not_before, int64_t p_seconds);
void fz_ca_free(fz_ca *p_ca);
int fz_ca_root_pem(const fz_ca *p_ca, char *r_out, size_t p_capacity);
int fz_ca_issue(fz_ca *p_ca, const char *p_csr_pem, const char *p_name, int64_t p_not_before, int64_t p_seconds,
		char *r_out, size_t p_capacity);
int fz_ca_export_root_key(const fz_ca *p_ca);

fz_key *fz_key_new(void);
void fz_key_free(fz_key *p_key);
int fz_key_csr_pem(fz_key *p_key, const char *p_name, char *r_out, size_t p_capacity);
int fz_key_pem(fz_key *p_key, char *r_out, size_t p_capacity);

int fz_verify(const char *p_root_pem, const char *p_cert_pem, const char *p_expected_name, int64_t p_now);

#ifdef __cplusplus
}
#endif
