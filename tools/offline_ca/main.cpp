// SPDX-FileCopyrightText: 2026 K. S. Ernest (iFire) Lee
// SPDX-License-Identifier: MIT
// The offline root on a desk (fz_ca_new_seeded). The seed arrives as one Base64 line on stdin, never in argv.
#include "fz_ca.h"

#include <mbedtls/base64.h>
#include <mbedtls/platform_util.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

namespace {

char g_csr[8192];
char g_pem[8192];

int usage() {
	fputs("usage: fz_offline_ca public\n"
		  "       fz_offline_ca root <root.pem> <not_before> <seconds>\n"
		  "       fz_offline_ca issue <name> <key.pem> <cert.pem> <not_before> <seconds>\n"
		  "with the seed as one Base64 line on stdin\n",
			stderr);
	return 2;
}

bool read_seed(unsigned char r_seed[FZ_SEED_BYTES]) {
	char line[128];
	unsigned char decoded[FZ_SEED_BYTES + 4];
	size_t got = 0;
	bool ok = fgets(line, sizeof line, stdin) != nullptr &&
			mbedtls_base64_decode(decoded, sizeof decoded, &got, reinterpret_cast<const unsigned char *>(line),
					strcspn(line, "\r\n")) == 0 &&
			got == FZ_SEED_BYTES;
	if (ok) {
		memcpy(r_seed, decoded, FZ_SEED_BYTES);
	}
	mbedtls_platform_zeroize(line, sizeof line);
	mbedtls_platform_zeroize(decoded, sizeof decoded);
	return ok;
}

bool parse_int64(const char *p_text, int64_t *r_value) {
	char *end = nullptr;
	long long value = strtoll(p_text, &end, 10);
	*r_value = int64_t(value);
	return end != p_text && *end == '\0';
}

bool write_file(const char *p_path, const char *p_text) {
	FILE *file = fopen(p_path, "wb");
	if (file == nullptr) {
		return false;
	}
	bool ok = fputs(p_text, file) >= 0;
	return fclose(file) == 0 && ok;
}

int fail(const char *p_what, int p_code) {
	fprintf(stderr, "%s: %d\n", p_what, p_code);
	return 3;
}

int issue(fz_ca *p_ca, const char *p_name, const char *p_key_path, const char *p_cert_path, int64_t p_not_before,
		int64_t p_seconds) {
	fz_key *key = fz_key_new();
	int ret = key == nullptr ? FZ_ERR_CRYPTO : fz_key_csr_pem(key, p_name, g_csr, sizeof g_csr);
	if (ret > 0) {
		ret = fz_ca_issue(p_ca, g_csr, p_name, p_not_before, p_seconds, g_pem, sizeof g_pem);
	}
	bool written = ret > 0 && write_file(p_cert_path, g_pem);
	if (written) {
		ret = fz_key_pem(key, g_pem, sizeof g_pem);
		written = ret > 0 && write_file(p_key_path, g_pem);
	}
	mbedtls_platform_zeroize(g_pem, sizeof g_pem);
	fz_key_free(key);
	if (ret <= 0) {
		return fail("issue", ret);
	}
	return written ? 0 : fail("write", ret);
}

} // namespace

int main(int argc, char **argv) {
	const bool is_public = argc == 2 && strcmp(argv[1], "public") == 0;
	const bool is_root = argc == 5 && strcmp(argv[1], "root") == 0;
	const bool is_issue = argc == 7 && strcmp(argv[1], "issue") == 0;
	int64_t not_before = int64_t(time(nullptr));
	int64_t seconds = 60;
	if (!(is_public || (is_root && parse_int64(argv[3], &not_before) && parse_int64(argv[4], &seconds)) ||
				is_issue)) {
		return usage();
	}
	int64_t leaf_not_before = 0;
	int64_t leaf_seconds = 0;
	if (is_issue && !(parse_int64(argv[5], &leaf_not_before) && parse_int64(argv[6], &leaf_seconds))) {
		return usage();
	}
	if (fz_crypto_init() != 0) {
		return fail("crypto", FZ_ERR_CRYPTO);
	}
	unsigned char seed[FZ_SEED_BYTES];
	if (!read_seed(seed)) {
		fputs("seed: expected 32 bytes as one Base64 line on stdin\n", stderr);
		return 2;
	}
	fz_ca *ca = fz_ca_new_seeded(seed, sizeof seed, not_before, seconds);
	mbedtls_platform_zeroize(seed, sizeof seed);
	if (ca == nullptr) {
		return fail("ca", FZ_ERR_CRYPTO);
	}
	int status = 0;
	if (is_public) {
		int ret = fz_ca_root_public_hex(ca, g_pem, sizeof g_pem);
		status = ret > 0 ? (puts(g_pem) >= 0 ? 0 : fail("write", ret)) : fail("public", ret);
	} else if (is_root) {
		int ret = fz_ca_root_pem(ca, g_pem, sizeof g_pem);
		status = ret > 0 ? (write_file(argv[2], g_pem) ? 0 : fail("write", ret)) : fail("root", ret);
	} else {
		status = issue(ca, argv[2], argv[3], argv[4], leaf_not_before, leaf_seconds);
	}
	fz_ca_free(ca);
	return status;
}
