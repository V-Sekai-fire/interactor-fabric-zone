// SPDX-FileCopyrightText: 2026 K. S. Ernest (iFire) Lee
// SPDX-License-Identifier: MIT
// fz_seal: the key this desk's own OS holds for the offline root's seed. Secrets cross only as one hex
// line on stdin or stdout; a refusal is a distinct exit status and a line on stderr.
#pragma once

#include <stddef.h>

#include <vector>

namespace fz_seal {

enum Status {
	STATUS_OK = 0,
	STATUS_USAGE = 2,
	STATUS_UNAVAILABLE = 3,
	STATUS_REFUSED = 4,
	STATUS_IO = 5,
	STATUS_EXISTS = 6,
	STATUS_NOT_FOUND = 7,
	STATUS_CANCELLED = 8,
	STATUS_INPUT = 9,
};

typedef std::vector<unsigned char> Bytes;

void wipe(void *p_data, size_t p_size);
void wipe(Bytes &r_bytes);
bool read_hex_line(Bytes &r_bytes, size_t p_max_bytes);
bool write_hex_line(const unsigned char *p_bytes, size_t p_count);
int fail(int p_status, const char *p_what);
int fail_code(int p_status, const char *p_what, long p_code);

const char *platform_usage();
int platform_main(int p_argc, char **p_argv);

} // namespace fz_seal
