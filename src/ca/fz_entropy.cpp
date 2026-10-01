// SPDX-FileCopyrightText: 2026 K. S. Ernest (iFire) Lee
// SPDX-License-Identifier: MIT
#include "fz_ca.h"

#include <mbedtls/platform.h>
#include <psa/crypto.h>

#include <errno.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#else
#include <sys/random.h>
#endif

namespace {

constexpr size_t kPoolCapacity = 65536;

unsigned char g_pool[kPoolCapacity];
size_t g_pool_head = 0;
size_t g_pool_tail = 0;
bool g_force_host = false;
int g_source = FZ_ENTROPY_NONE;

bool os_draw(unsigned char *r_out, size_t p_count) {
	if (g_force_host) {
		return false;
	}
#ifdef _WIN32
	return BCryptGenRandom(nullptr, r_out, ULONG(p_count), BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
#else
	size_t got = 0;
	while (got < p_count) {
		ssize_t n = getrandom(r_out + got, p_count - got, 0);
		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			return false;
		}
		if (n == 0) {
			return false;
		}
		got += size_t(n);
	}
	return true;
#endif
}

bool host_draw(unsigned char *r_out, size_t p_count) {
	if (g_pool_tail - g_pool_head < p_count) {
		return false;
	}
	memcpy(r_out, g_pool + g_pool_head, p_count);
	memset(g_pool + g_pool_head, 0, p_count);
	g_pool_head += p_count;
	return true;
}

bool all_zero(const unsigned char *p_bytes, size_t p_count) {
	unsigned char any = 0;
	for (size_t i = 0; i < p_count; ++i) {
		any |= p_bytes[i];
	}
	return any == 0;
}

} // namespace

extern "C" int fz_entropy_feed(const unsigned char *p_bytes, size_t p_count) {
	if (g_pool_head > 0) {
		memmove(g_pool, g_pool + g_pool_head, g_pool_tail - g_pool_head);
		g_pool_tail -= g_pool_head;
		g_pool_head = 0;
	}
	if (p_count > kPoolCapacity - g_pool_tail) {
		return FZ_ERR_BUFFER;
	}
	memcpy(g_pool + g_pool_tail, p_bytes, p_count);
	g_pool_tail += p_count;
	return 0;
}

extern "C" size_t fz_entropy_pool_left(void) {
	return g_pool_tail - g_pool_head;
}

extern "C" void fz_entropy_force_host(int p_on) {
	g_force_host = p_on != 0;
}

extern "C" int fz_entropy_source(void) {
	return g_source;
}

// Draws 32 bytes from the OS source; if that errors or returns all zeros, from the host pool.
extern "C" int fz_entropy_probe(unsigned char *r_out32) {
	if (os_draw(r_out32, 32) && !all_zero(r_out32, 32)) {
		g_source = FZ_ENTROPY_OS;
		return g_source;
	}
	g_force_host = true;
	if (host_draw(r_out32, 32) && !all_zero(r_out32, 32)) {
		g_source = FZ_ENTROPY_HOST;
		return g_source;
	}
	g_source = FZ_ENTROPY_NONE;
	return FZ_ERR_ENTROPY;
}

extern "C" int mbedtls_platform_get_entropy(psa_driver_get_entropy_flags_t p_flags, size_t *r_estimate_bits,
		unsigned char *r_output, size_t p_output_size) {
	if (p_flags != 0) {
		return PSA_ERROR_NOT_SUPPORTED;
	}
	if (os_draw(r_output, p_output_size) || host_draw(r_output, p_output_size)) {
		*r_estimate_bits = 8 * p_output_size;
		return 0;
	}
	*r_estimate_bits = 0;
	return PSA_ERROR_INSUFFICIENT_ENTROPY;
}
