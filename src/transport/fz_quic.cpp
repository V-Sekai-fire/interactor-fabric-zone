// SPDX-FileCopyrightText: 2026 K. S. Ernest (iFire) Lee
// SPDX-License-Identifier: MIT
#include "fz_quic.h"

#include <mbedtls/x509_crt.h>
#include <picotls.h>
#include <picoquic.h>
#include <picoquic_crypto_provider_api.h>
#include <picoquic_internal.h>
#include <h3zero_common.h>
#include <pico_webtransport.h>
#include <ptls_mbedtls.h>
#include <tls_api.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

// Declared in ptls_mbedtls_sign.c but not in its header: a verifier over trust roots already parsed.
extern "C" ptls_mbedtls_verify_certificate_t *ptls_mbedssl_init_verify_certificate_complete(mbedtls_x509_crt *p_trust_ca,
		mbedtls_x509_crl *p_trust_crl, int (*p_f_vrfy)(void *, mbedtls_x509_crt *, int, uint32_t *), void *p_vrfy);

// picoquic_ptls_minicrypto.c is not compiled; tls_api.c still references its loader.
extern "C" void picoquic_ptls_minicrypto_load(int) {
}

// now_us is the only clock picoquic reads (its simulated-time pointer), set from the host on every call.
struct fz_quic {
	uint64_t now_us;
	picoquic_quic_t *quic;
	picoquic_cnx_t *cnx;
	int is_server;
	picohttp_server_path_item_t path;
	picohttp_server_parameters_t server;
	h3zero_callback_ctx_t *h3;
	h3zero_stream_ctx_t *control;
	uint64_t control_stream_id;
	int session;
	uint8_t outgoing[FZ_WT_DATAGRAM_MAX];
	size_t outgoing_count;
	uint8_t incoming[FZ_WT_DATAGRAM_MAX];
	size_t incoming_count;
	uint64_t received;
};

namespace {

// Once, before the first context: a later reset reloads mbedTLS under contexts that hold its suites.
bool tls_ready() {
	static int s_ready = -1;
	if (s_ready < 0) {
		s_ready = ptls_mbedtls_init() == 0 ? 1 : 0;
		if (s_ready == 1) {
			picoquic_tls_api_reset(TLS_API_INIT_FLAGS_NO_MINICRYPTO | TLS_API_INIT_FLAGS_NO_OPENSSL | TLS_API_INIT_FLAGS_NO_FUSION);
		}
	}
	return s_ready == 1;
}

// The WebTransport session on FZ_WT_PATH: the server accepts a CONNECT and binds its stream prefix; both
// ends then trade datagrams on it.
int on_session_event(picoquic_cnx_t *p_cnx, uint8_t *p_bytes, size_t p_length, picohttp_call_back_event_t p_event,
		h3zero_stream_ctx_t *p_stream, void *p_app) {
	fz_quic *self = static_cast<fz_quic *>(p_app);
	switch (p_event) {
		case picohttp_callback_connect: {
			h3zero_callback_ctx_t *h3 = static_cast<h3zero_callback_ctx_t *>(picoquic_get_callback_context(p_cnx));
			p_stream->ps.stream_state.control_stream_id = p_stream->stream_id;
			p_stream->path_callback = on_session_event;
			p_stream->path_callback_ctx = self;
			self->control_stream_id = p_stream->stream_id;
			self->cnx = p_cnx;
			self->session = FZ_WT_UP;
			return h3zero_declare_stream_prefix(h3, p_stream->stream_id, on_session_event, self);
		}
		case picohttp_callback_connect_accepted:
			self->session = FZ_WT_UP;
			return 0;
		case picohttp_callback_connect_refused:
			self->session = FZ_WT_REFUSED;
			return 0;
		case picohttp_callback_post_datagram:
			if (p_length <= sizeof self->incoming) {
				memcpy(self->incoming, p_bytes, p_length);
				self->incoming_count = p_length;
				self->received += 1;
			}
			return 0;
		case picohttp_callback_provide_datagram:
			if (self->outgoing_count > 0 && self->outgoing_count <= p_length) {
				uint8_t *buffer = h3zero_provide_datagram_buffer(p_bytes, self->outgoing_count, 0);
				if (buffer == nullptr) {
					return -1;
				}
				memcpy(buffer, self->outgoing, self->outgoing_count);
				self->outgoing_count = 0;
			}
			return 0;
		default:
			return 0;
	}
}

bool set_chain(picoquic_quic_t *p_quic, const char *p_cert_pem) {
	mbedtls_x509_crt crt;
	mbedtls_x509_crt_init(&crt);
	if (mbedtls_x509_crt_parse(&crt, reinterpret_cast<const unsigned char *>(p_cert_pem), strlen(p_cert_pem) + 1) != 0) {
		mbedtls_x509_crt_free(&crt);
		return false;
	}
	ptls_iovec_t *certs = static_cast<ptls_iovec_t *>(malloc(sizeof(ptls_iovec_t)));
	uint8_t *der = static_cast<uint8_t *>(malloc(crt.raw.len));
	memcpy(der, crt.raw.p, crt.raw.len);
	certs[0] = ptls_iovec_init(der, crt.raw.len);
	mbedtls_x509_crt_free(&crt);
	picoquic_set_tls_certificate_chain(p_quic, certs, 1);
	return true;
}

bool set_verifier(picoquic_quic_t *p_quic, const char *p_root_pem) {
	mbedtls_x509_crt *roots = static_cast<mbedtls_x509_crt *>(malloc(sizeof(mbedtls_x509_crt)));
	mbedtls_x509_crt_init(roots);
	if (mbedtls_x509_crt_parse(roots, reinterpret_cast<const unsigned char *>(p_root_pem), strlen(p_root_pem) + 1) != 0) {
		mbedtls_x509_crt_free(roots);
		free(roots);
		return false;
	}
	ptls_mbedtls_verify_certificate_t *verifier = ptls_mbedssl_init_verify_certificate_complete(roots, nullptr, nullptr, nullptr);
	if (verifier == nullptr) {
		mbedtls_x509_crt_free(roots);
		free(roots);
		return false;
	}
	picoquic_set_verify_certificate_callback(p_quic, &verifier->super, ptls_mbedtls_dispose_verify_certificate);
	return true;
}

void to_sockaddr(uint32_t p_ip, uint16_t p_port, struct sockaddr_in *r_addr) {
	memset(r_addr, 0, sizeof *r_addr);
	r_addr->sin_family = AF_INET;
	r_addr->sin_port = htons(p_port);
	r_addr->sin_addr.s_addr = htonl(p_ip);
}

} // namespace

extern "C" fz_quic *fz_quic_new(int p_is_server, const char *p_cert_pem, const char *p_key_pem, const char *p_root_pem,
		uint64_t p_now_us) {
	if (!tls_ready()) {
		return nullptr;
	}
	fz_quic *self = new fz_quic;
	self->now_us = p_now_us;
	self->cnx = nullptr;
	self->is_server = p_is_server;
	self->h3 = nullptr;
	self->control = nullptr;
	self->control_stream_id = UINT64_MAX;
	self->session = FZ_WT_NONE;
	self->outgoing_count = 0;
	self->incoming_count = 0;
	self->received = 0;
	self->path.path = FZ_WT_PATH;
	self->path.path_length = strlen(FZ_WT_PATH);
	self->path.path_callback = on_session_event;
	self->path.path_app_ctx = self;
	self->server.web_folder = nullptr;
	self->server.path_table = &self->path;
	self->server.path_table_nb = 1;
	picoquic_quic_t *quic = picoquic_create(8, nullptr, nullptr, nullptr, FZ_QUIC_ALPN, h3zero_callback,
			p_is_server ? &self->server : nullptr, nullptr, nullptr, nullptr, p_now_us, &self->now_us, nullptr, nullptr, 0);
	if (quic == nullptr) {
		delete self;
		return nullptr;
	}
	bool ok = set_chain(quic, p_cert_pem) &&
			picoquic_set_tls_key(quic, reinterpret_cast<const uint8_t *>(p_key_pem), strlen(p_key_pem)) == 0 &&
			set_verifier(quic, p_root_pem);
	if (!ok) {
		picoquic_free(quic);
		delete self;
		return nullptr;
	}
	// The chain and key come from memory, so picoquic_create saw no files and marked this a client.
	if (p_is_server) {
		picoquic_enforce_client_only(quic, 0);
		picoquic_set_client_authentication(quic, 1);
		picowt_set_default_transport_parameters(quic);
	}
	self->quic = quic;
	return self;
}

extern "C" void fz_quic_free(fz_quic *p_quic) {
	if (p_quic == nullptr) {
		return;
	}
	picoquic_free(p_quic->quic);
	delete p_quic;
}

extern "C" int fz_quic_connect(fz_quic *p_quic, uint32_t p_ip, uint16_t p_port, const char *p_server_name,
		uint64_t p_now_us) {
	p_quic->now_us = p_now_us;
	struct sockaddr_in to;
	to_sockaddr(p_ip, p_port, &to);
	if (picowt_prepare_client_cnx(p_quic->quic, reinterpret_cast<struct sockaddr *>(&to), &p_quic->cnx, &p_quic->h3,
				&p_quic->control, p_now_us, p_server_name) != 0) {
		return -1;
	}
	p_quic->control_stream_id = p_quic->control->stream_id;
	if (picowt_connect(p_quic->cnx, p_quic->h3, p_quic->control, p_server_name, FZ_WT_PATH, on_session_event, p_quic,
				nullptr) != 0) {
		return -1;
	}
	return picoquic_start_client_cnx(p_quic->cnx);
}

extern "C" int fz_quic_incoming(fz_quic *p_quic, const uint8_t *p_bytes, size_t p_count, uint32_t p_from_ip,
		uint16_t p_from_port, uint32_t p_to_ip, uint16_t p_to_port, uint64_t p_now_us) {
	p_quic->now_us = p_now_us;
	struct sockaddr_in from;
	struct sockaddr_in to;
	to_sockaddr(p_from_ip, p_from_port, &from);
	to_sockaddr(p_to_ip, p_to_port, &to);
	int ret = picoquic_incoming_packet(p_quic->quic, const_cast<uint8_t *>(p_bytes), p_count,
			reinterpret_cast<struct sockaddr *>(&from), reinterpret_cast<struct sockaddr *>(&to), 0, 0, p_now_us);
	if (p_quic->is_server && p_quic->cnx == nullptr) {
		p_quic->cnx = picoquic_get_first_cnx(p_quic->quic);
	}
	return ret;
}

extern "C" int fz_quic_prepare(fz_quic *p_quic, uint64_t p_now_us, uint8_t *r_out, size_t p_capacity, size_t *r_count,
		uint32_t *r_to_ip, uint16_t *r_to_port) {
	p_quic->now_us = p_now_us;
	struct sockaddr_storage to;
	struct sockaddr_storage from;
	memset(&to, 0, sizeof to);
	int if_index = 0;
	picoquic_connection_id_t log_cid;
	picoquic_cnx_t *last = nullptr;
	*r_count = 0;
	int ret = picoquic_prepare_next_packet(p_quic->quic, p_now_us, r_out, p_capacity, r_count, &to, &from, &if_index,
			&log_cid, &last);
	if (ret == 0 && *r_count > 0 && to.ss_family == AF_INET) {
		const struct sockaddr_in *in = reinterpret_cast<const struct sockaddr_in *>(&to);
		*r_to_ip = ntohl(in->sin_addr.s_addr);
		*r_to_port = ntohs(in->sin_port);
	}
	return ret;
}

extern "C" int fz_quic_state(const fz_quic *p_quic) {
	if (p_quic->cnx == nullptr) {
		return FZ_QUIC_IDLE;
	}
	picoquic_state_enum state = picoquic_get_cnx_state(p_quic->cnx);
	if (state >= picoquic_state_disconnecting) {
		return FZ_QUIC_CLOSED;
	}
	if (state == picoquic_state_ready || state == picoquic_state_client_ready_start) {
		return FZ_QUIC_READY;
	}
	return FZ_QUIC_HANDSHAKE;
}

extern "C" uint64_t fz_quic_error(const fz_quic *p_quic) {
	if (p_quic->cnx == nullptr) {
		return 0;
	}
	uint64_t local = picoquic_get_local_error(p_quic->cnx);
	return local != 0 ? local : picoquic_get_remote_error(p_quic->cnx);
}

extern "C" uint64_t fz_quic_next_wake(fz_quic *p_quic, uint64_t p_now_us) {
	p_quic->now_us = p_now_us;
	return picoquic_get_next_wake_time(p_quic->quic, p_now_us);
}

extern "C" int fz_quic_session(const fz_quic *p_quic) {
	return p_quic->session;
}

extern "C" int fz_quic_send_datagram(fz_quic *p_quic, const uint8_t *p_bytes, size_t p_count) {
	if (p_quic->session != FZ_WT_UP || p_count == 0 || p_count > sizeof p_quic->outgoing) {
		return -1;
	}
	memcpy(p_quic->outgoing, p_bytes, p_count);
	p_quic->outgoing_count = p_count;
	return h3zero_set_datagram_ready(p_quic->cnx, p_quic->control_stream_id);
}

extern "C" size_t fz_quic_take_datagram(fz_quic *p_quic, uint8_t *r_out, size_t p_capacity) {
	size_t n = p_quic->incoming_count;
	if (n == 0 || n > p_capacity) {
		return 0;
	}
	memcpy(r_out, p_quic->incoming, n);
	p_quic->incoming_count = 0;
	return n;
}
