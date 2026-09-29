// SPDX-FileCopyrightText: 2026 K. S. Ernest (iFire) Lee
// SPDX-License-Identifier: MIT
// Lean bindings for src/ca/fz_ca.h. Handles cross as USize; PEM text as String.
#include "fz_ca.h"

#include <lean/lean.h>

#include <cstdint>
#include <cstdio>

namespace {

char g_buffer[8192];

lean_obj_res pem_or_code(int p_ret) {
	if (p_ret < 0) {
		snprintf(g_buffer, sizeof g_buffer, "ERR %d", p_ret);
	}
	return lean_io_result_mk_ok(lean_mk_string(g_buffer));
}

} // namespace

extern "C" lean_obj_res fzl_probe(lean_obj_arg) {
	unsigned char out[32];
	return lean_io_result_mk_ok(lean_box_uint32(uint32_t(int32_t(fz_entropy_probe(out)))));
}

extern "C" lean_obj_res fzl_crypto_init(lean_obj_arg) {
	return lean_io_result_mk_ok(lean_box_uint32(uint32_t(fz_crypto_init())));
}

extern "C" lean_obj_res fzl_force_host(uint8_t p_on, lean_obj_arg) {
	fz_entropy_force_host(p_on);
	return lean_io_result_mk_ok(lean_box(0));
}

extern "C" lean_obj_res fzl_feed(b_lean_obj_arg p_bytes, lean_obj_arg) {
	int ret = fz_entropy_feed(lean_sarray_cptr(p_bytes), lean_sarray_size(p_bytes));
	return lean_io_result_mk_ok(lean_box_uint32(uint32_t(int32_t(ret))));
}

extern "C" uint8_t fzl_name_allowed(b_lean_obj_arg p_name) {
	return uint8_t(fz_name_allowed(lean_string_cstr(p_name)));
}

extern "C" lean_obj_res fzl_ca_new(uint64_t p_not_before, uint64_t p_seconds, lean_obj_arg) {
	fz_ca *ca = fz_ca_new(int64_t(p_not_before), int64_t(p_seconds));
	return lean_io_result_mk_ok(lean_box_usize(reinterpret_cast<size_t>(ca)));
}

extern "C" lean_obj_res fzl_ca_root(size_t p_ca, lean_obj_arg) {
	return pem_or_code(fz_ca_root_pem(reinterpret_cast<fz_ca *>(p_ca), g_buffer, sizeof g_buffer));
}

extern "C" lean_obj_res fzl_ca_export(size_t p_ca, lean_obj_arg) {
	return lean_io_result_mk_ok(lean_box_uint32(uint32_t(fz_ca_export_root_key(reinterpret_cast<fz_ca *>(p_ca)))));
}

extern "C" lean_obj_res fzl_ca_issue(size_t p_ca, b_lean_obj_arg p_csr, b_lean_obj_arg p_name, uint64_t p_not_before,
		uint64_t p_seconds, lean_obj_arg) {
	return pem_or_code(fz_ca_issue(reinterpret_cast<fz_ca *>(p_ca), lean_string_cstr(p_csr), lean_string_cstr(p_name),
			int64_t(p_not_before), int64_t(p_seconds), g_buffer, sizeof g_buffer));
}

extern "C" lean_obj_res fzl_key_new(lean_obj_arg) {
	return lean_io_result_mk_ok(lean_box_usize(reinterpret_cast<size_t>(fz_key_new())));
}

extern "C" lean_obj_res fzl_key_csr(size_t p_key, b_lean_obj_arg p_name, lean_obj_arg) {
	return pem_or_code(fz_key_csr_pem(reinterpret_cast<fz_key *>(p_key), lean_string_cstr(p_name), g_buffer, sizeof g_buffer));
}

extern "C" lean_obj_res fzl_key_pem(size_t p_key, lean_obj_arg) {
	return pem_or_code(fz_key_pem(reinterpret_cast<fz_key *>(p_key), g_buffer, sizeof g_buffer));
}

extern "C" lean_obj_res fzl_verify(b_lean_obj_arg p_root, b_lean_obj_arg p_cert, b_lean_obj_arg p_name, uint64_t p_now,
		lean_obj_arg) {
	int ret = fz_verify(lean_string_cstr(p_root), lean_string_cstr(p_cert), lean_string_cstr(p_name), int64_t(p_now));
	return lean_io_result_mk_ok(lean_box_uint32(uint32_t(ret)));
}
