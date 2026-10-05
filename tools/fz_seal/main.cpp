// SPDX-FileCopyrightText: 2026 K. S. Ernest (iFire) Lee
// SPDX-License-Identifier: MIT
#include "fz_seal.h"

#include <stdio.h>
#include <string.h>

namespace fz_seal {

void wipe(void *p_data, size_t p_size) {
	volatile unsigned char *bytes = static_cast<volatile unsigned char *>(p_data);
	for (size_t i = 0; i < p_size; ++i) {
		bytes[i] = 0;
	}
}

void wipe(Bytes &r_bytes) {
	if (!r_bytes.empty()) {
		wipe(r_bytes.data(), r_bytes.size());
	}
	r_bytes.clear();
}

namespace {

int hex_value(int p_char) {
	if (p_char >= '0' && p_char <= '9') {
		return p_char - '0';
	}
	if (p_char >= 'a' && p_char <= 'f') {
		return p_char - 'a' + 10;
	}
	if (p_char >= 'A' && p_char <= 'F') {
		return p_char - 'A' + 10;
	}
	return -1;
}

} // namespace

bool read_hex_line(Bytes &r_bytes, size_t p_max_bytes) {
	wipe(r_bytes);
	int high = -1;
	bool ok = true;
	for (int c = getchar(); c != EOF && c != '\n'; c = getchar()) {
		if (c == '\r') {
			continue;
		}
		int value = hex_value(c);
		if (value < 0 || (high < 0 && r_bytes.size() >= p_max_bytes)) {
			ok = false;
			continue;
		}
		if (high < 0) {
			high = value;
		} else {
			r_bytes.push_back(static_cast<unsigned char>(high << 4 | value));
			high = -1;
		}
	}
	if (!ok || high >= 0 || r_bytes.empty()) {
		wipe(r_bytes);
		return false;
	}
	return true;
}

bool write_hex_line(const unsigned char *p_bytes, size_t p_count) {
	static const char digits[] = "0123456789abcdef";
	char pair[2];
	for (size_t i = 0; i < p_count; ++i) {
		pair[0] = digits[p_bytes[i] >> 4];
		pair[1] = digits[p_bytes[i] & 15];
		if (fwrite(pair, 1, 2, stdout) != 2) {
			return false;
		}
	}
	wipe(pair, sizeof pair);
	return fputc('\n', stdout) == '\n' && fflush(stdout) == 0;
}

int fail(int p_status, const char *p_what) {
	fprintf(stderr, "fz_seal: %s\n", p_what);
	return p_status;
}

int fail_code(int p_status, const char *p_what, long p_code) {
	fprintf(stderr, "fz_seal: %s (%ld, 0x%08lx)\n", p_what, p_code, static_cast<unsigned long>(p_code));
	return p_status;
}

} // namespace fz_seal

int main(int argc, char **argv) {
	if (argc < 2) {
		fputs(fz_seal::platform_usage(), stderr);
		return fz_seal::STATUS_USAGE;
	}
	return fz_seal::platform_main(argc, argv);
}
