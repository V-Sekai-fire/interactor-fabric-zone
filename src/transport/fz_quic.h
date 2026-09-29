// SPDX-FileCopyrightText: 2026 K. S. Ernest (iFire) Lee
// SPDX-License-Identifier: MIT
// QUIC with mutual TLS and a WebTransport session over HTTP/3, driven by datagrams the host relays
// and the time it passes in: no sockets, no threads, no clock of its own. Both ends present a
// certificate from ca.elf and accept only that root. Addresses are IPv4 in host byte order.
#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
	FZ_QUIC_IDLE = 0,
	FZ_QUIC_HANDSHAKE = 1,
	FZ_QUIC_READY = 2,
	FZ_QUIC_CLOSED = 3,
};

#define FZ_QUIC_ALPN "h3"
#define FZ_WT_PATH "/zone"
#define FZ_WT_DATAGRAM_MAX 1200

enum {
	FZ_WT_NONE = 0,
	FZ_WT_UP = 1,
	FZ_WT_REFUSED = 2,
};

typedef struct fz_quic fz_quic;

fz_quic *fz_quic_new(int p_is_server, const char *p_cert_pem, const char *p_key_pem, const char *p_root_pem,
		uint64_t p_now_us);
void fz_quic_free(fz_quic *p_quic);
int fz_quic_connect(fz_quic *p_quic, uint32_t p_ip, uint16_t p_port, const char *p_server_name, uint64_t p_now_us);
int fz_quic_incoming(fz_quic *p_quic, const uint8_t *p_bytes, size_t p_count, uint32_t p_from_ip, uint16_t p_from_port,
		uint32_t p_to_ip, uint16_t p_to_port, uint64_t p_now_us);
int fz_quic_prepare(fz_quic *p_quic, uint64_t p_now_us, uint8_t *r_out, size_t p_capacity, size_t *r_count,
		uint32_t *r_to_ip, uint16_t *r_to_port);
int fz_quic_state(const fz_quic *p_quic);
uint64_t fz_quic_error(const fz_quic *p_quic);
uint64_t fz_quic_next_wake(fz_quic *p_quic, uint64_t p_now_us);

// The WebTransport session on FZ_WT_PATH over the connection, and datagrams on it (one queued each way).
int fz_quic_session(const fz_quic *p_quic);
int fz_quic_send_datagram(fz_quic *p_quic, const uint8_t *p_bytes, size_t p_count);
size_t fz_quic_take_datagram(fz_quic *p_quic, uint8_t *r_out, size_t p_capacity);

#ifdef __cplusplus
}
#endif
