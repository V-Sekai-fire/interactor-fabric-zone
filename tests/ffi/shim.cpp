// SPDX-FileCopyrightText: 2026 K. S. Ernest (iFire) Lee
// SPDX-License-Identifier: MIT
// Lean bindings for src/ca/fz_ca.h. Handles cross as USize; PEM text as String.
#include "fz_ca.h"
#include "fz_quic.h"

#include <lean/lean.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string.h>

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

// Server and client in one process, datagrams handed across in memory 5 ms after they leave (a round
// trip of zero would make QUIC's loss timer fire the moment a packet is sent). Returns client state * 10 +
// server state after the handshake settles or 200 rounds pass, plus 100 when the WebTransport session
// is up at both ends, plus 1000 when a datagram then crosses each way intact and no relayed datagram
// holds its bytes in the clear. With p_tamper, one byte of each client datagram is flipped once the
// hello is queued, so it must not arrive.
extern "C" lean_obj_res fzl_quic_handshake(b_lean_obj_arg p_server_cert, b_lean_obj_arg p_server_key,
		b_lean_obj_arg p_server_root, b_lean_obj_arg p_client_cert, b_lean_obj_arg p_client_key,
		b_lean_obj_arg p_client_root, b_lean_obj_arg p_server_name, uint8_t p_tamper, lean_obj_arg) {
	uint64_t t = 1000000;
	fz_quic *server = fz_quic_new(1, lean_string_cstr(p_server_cert), lean_string_cstr(p_server_key),
			lean_string_cstr(p_server_root), t);
	fz_quic *client = fz_quic_new(0, lean_string_cstr(p_client_cert), lean_string_cstr(p_client_key),
			lean_string_cstr(p_client_root), t);
	uint32_t result = 99;
	if (server != nullptr && client != nullptr) {
		const uint32_t ip = 0x7f000001;
		fz_quic_connect(client, ip, 4433, lean_string_cstr(p_server_name), t);
		uint8_t datagram[1600];
		size_t count = 0;
		uint32_t to_ip = 0;
		uint16_t to_port = 0;
		for (int round = 0; round < 200; ++round) {
			t += 1000;
			for (int k = 0; k < 20; ++k) {
				fz_quic_prepare(client, t, datagram, sizeof datagram, &count, &to_ip, &to_port);
				if (count == 0) {
					break;
				}
				fz_quic_incoming(server, datagram, count, ip, 50000, ip, 4433, t + 5000);
			}
			t += 5000;
			for (int k = 0; k < 20; ++k) {
				fz_quic_prepare(server, t, datagram, sizeof datagram, &count, &to_ip, &to_port);
				if (count == 0) {
					break;
				}
				fz_quic_incoming(client, datagram, count, ip, 4433, ip, 50000, t + 5000);
			}
			t += 5000;
			int c = fz_quic_state(client);
			int s = fz_quic_state(server);
			if ((c == FZ_QUIC_READY && s == FZ_QUIC_READY) || c == FZ_QUIC_CLOSED || s == FZ_QUIC_CLOSED) {
				break;
			}
		}
		result = uint32_t(fz_quic_state(client) * 10 + fz_quic_state(server));
		const uint8_t hello[] = "hello zone";
		const uint8_t reply[] = "hello player";
		uint8_t got[1600];
		bool sent_hello = false;
		bool sent_reply = false;
		bool hello_ok = false;
		bool reply_ok = false;
		bool plaintext_seen = false;
		for (int round = 0; result == 22 && round < 400 && !reply_ok; ++round) {
			t += 1000;
			if (!sent_hello && fz_quic_session(client) == FZ_WT_UP && fz_quic_session(server) == FZ_WT_UP) {
				sent_hello = fz_quic_send_datagram(client, hello, sizeof hello) == 0;
			}
			for (int k = 0; k < 20; ++k) {
				fz_quic_prepare(client, t, datagram, sizeof datagram, &count, &to_ip, &to_port);
				if (count == 0) {
					break;
				}
				plaintext_seen = plaintext_seen || memmem(datagram, count, "hello", 5) != nullptr;
				if (p_tamper && sent_hello) {
					datagram[count - 1] ^= 0x01;
				}
				fz_quic_incoming(server, datagram, count, ip, 50000, ip, 4433, t + 5000);
			}
			t += 5000;
			size_t n = fz_quic_take_datagram(server, got, sizeof got);
			if (n == sizeof hello && memcmp(got, hello, n) == 0) {
				hello_ok = true;
				sent_reply = fz_quic_send_datagram(server, reply, sizeof reply) == 0;
			}
			for (int k = 0; k < 20; ++k) {
				fz_quic_prepare(server, t, datagram, sizeof datagram, &count, &to_ip, &to_port);
				if (count == 0) {
					break;
				}
				plaintext_seen = plaintext_seen || memmem(datagram, count, "hello", 5) != nullptr;
				fz_quic_incoming(client, datagram, count, ip, 4433, ip, 50000, t + 5000);
			}
			t += 5000;
			n = fz_quic_take_datagram(client, got, sizeof got);
			reply_ok = sent_reply && n == sizeof reply && memcmp(got, reply, n) == 0;
		}
		if (fz_quic_session(client) == FZ_WT_UP && fz_quic_session(server) == FZ_WT_UP) {
			result += 100;
		}
		if (hello_ok && reply_ok && !plaintext_seen) {
			result += 1000;
		}
	}
	fz_quic_free(client);
	fz_quic_free(server);
	return lean_io_result_mk_ok(lean_box_uint32(result));
}
