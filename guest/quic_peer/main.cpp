// SPDX-FileCopyrightText: 2026 K. S. Ernest (iFire) Lee
// SPDX-License-Identifier: MIT
// quic_peer.elf: one end of a QUIC connection with mutual TLS and a WebTransport session on it. Its private key is made here and never
// leaves; the host carries the CSR to ca.elf and the certificate back, relays each datagram through
// PacketPeerUDP, and passes the time in.
#include <api.hpp>

#include "fz_ca.h"
#include "fz_quic.h"

#include <cstdint>
#include <string>
#include <vector>

namespace {

fz_key *g_key = nullptr;
fz_quic *g_quic = nullptr;
char g_buffer[8192];
uint8_t g_datagram[1600];

Variant text(const std::string &p_s) {
	return Variant(String(p_s));
}

bool crypto_ready() {
	static int s_ready = -1;
	if (s_ready < 0) {
		unsigned char probe[32];
		s_ready = fz_entropy_probe(probe) > 0 && fz_crypto_init() == 0 ? 1 : 0;
	}
	return s_ready == 1;
}

} // namespace

static Variant quic_entropy_feed(PackedArray<uint8_t> p_bytes) {
	std::vector<uint8_t> bytes = p_bytes.fetch();
	return text(fz_entropy_feed(bytes.data(), bytes.size()) == 0 ? "ok" : "FAIL: pool full");
}

static Variant quic_make_key(String p_name) {
	if (!crypto_ready()) {
		return text("FAIL: no entropy");
	}
	if (g_key == nullptr) {
		g_key = fz_key_new();
	}
	std::string name = p_name.utf8();
	if (g_key == nullptr || fz_key_csr_pem(g_key, name.c_str(), g_buffer, sizeof g_buffer) < 0) {
		return text("FAIL: key or CSR");
	}
	return text(g_buffer);
}

static Variant quic_open(bool p_is_server, String p_cert_pem, String p_root_pem, int64_t p_now_us) {
	if (g_key == nullptr || g_quic != nullptr) {
		return text("FAIL: make a key first, once");
	}
	static char key_pem[4096];
	if (fz_key_pem(g_key, key_pem, sizeof key_pem) < 0) {
		return text("FAIL: key");
	}
	std::string cert = p_cert_pem.utf8();
	std::string root = p_root_pem.utf8();
	g_quic = fz_quic_new(p_is_server ? 1 : 0, cert.c_str(), key_pem, root.c_str(), uint64_t(p_now_us));
	return text(g_quic == nullptr ? "FAIL: certificate, key or root" : "ok");
}

static Variant quic_connect(int64_t p_ip, int64_t p_port, String p_server_name, int64_t p_now_us) {
	std::string name = p_server_name.utf8();
	return Variant(int64_t(g_quic == nullptr ? -1 :
			fz_quic_connect(g_quic, uint32_t(p_ip), uint16_t(p_port), name.c_str(), uint64_t(p_now_us))));
}

static Variant quic_incoming(PackedArray<uint8_t> p_datagram, int64_t p_from_ip, int64_t p_from_port, int64_t p_to_ip,
		int64_t p_to_port, int64_t p_now_us) {
	if (g_quic == nullptr) {
		return Variant(int64_t(-1));
	}
	std::vector<uint8_t> bytes = p_datagram.fetch();
	return Variant(int64_t(fz_quic_incoming(g_quic, bytes.data(), bytes.size(), uint32_t(p_from_ip), uint16_t(p_from_port),
			uint32_t(p_to_ip), uint16_t(p_to_port), uint64_t(p_now_us))));
}

// The next datagram to send, as {bytes, ip, port}; bytes is empty when there is none.
static Variant quic_prepare(int64_t p_now_us) {
	Dictionary d = Dictionary::Create();
	size_t count = 0;
	uint32_t ip = 0;
	uint16_t port = 0;
	if (g_quic != nullptr) {
		fz_quic_prepare(g_quic, uint64_t(p_now_us), g_datagram, sizeof g_datagram, &count, &ip, &port);
	}
	d["bytes"] = Variant(PackedArray<uint8_t>(g_datagram, count));
	d["ip"] = Variant(int64_t(ip));
	d["port"] = Variant(int64_t(port));
	return Variant(d);
}

static Variant quic_session() {
	return Variant(int64_t(g_quic == nullptr ? -1 : fz_quic_session(g_quic)));
}

static Variant quic_send_datagram(PackedArray<uint8_t> p_bytes) {
	if (g_quic == nullptr) {
		return Variant(int64_t(-1));
	}
	std::vector<uint8_t> bytes = p_bytes.fetch();
	return Variant(int64_t(fz_quic_send_datagram(g_quic, bytes.data(), bytes.size())));
}

static Variant quic_take_datagram() {
	size_t n = g_quic == nullptr ? 0 : fz_quic_take_datagram(g_quic, g_datagram, sizeof g_datagram);
	return Variant(PackedArray<uint8_t>(g_datagram, n));
}

static Variant quic_state() {

	return Variant(int64_t(g_quic == nullptr ? -1 : fz_quic_state(g_quic)));
}

static Variant quic_error() {
	return Variant(int64_t(g_quic == nullptr ? 0 : fz_quic_error(g_quic)));
}

int main() {
	ADD_API_FUNCTION(quic_entropy_feed, "String", "PackedByteArray bytes", "Host-supplied entropy, used when the OS source fails");
	ADD_API_FUNCTION(quic_make_key, "String", "String name", "Make this peer's key in guest memory; returns its CSR");
	ADD_API_FUNCTION(quic_open, "String", "bool is_server, String cert_pem, String root_pem, int now_us",
			"Open the QUIC context with the certificate ca.elf issued and the only root to trust");
	ADD_API_FUNCTION(quic_connect, "int", "int ip, int port, String server_name, int now_us", "Client: start the handshake");
	ADD_API_FUNCTION(quic_incoming, "int", "PackedByteArray datagram, int from_ip, int from_port, int to_ip, int to_port, int now_us",
			"A datagram the host received for this peer");
	ADD_API_FUNCTION(quic_prepare, "Dictionary", "int now_us", "The next datagram to send: {bytes, ip, port}");
	ADD_API_FUNCTION(quic_state, "int", "", "0 idle, 1 handshake, 2 ready, 3 closed");
	ADD_API_FUNCTION(quic_session, "int", "", "The WebTransport session: 0 none, 1 up, 2 refused");
	ADD_API_FUNCTION(quic_send_datagram, "int", "PackedByteArray bytes", "Queue one WebTransport datagram");
	ADD_API_FUNCTION(quic_take_datagram, "PackedByteArray", "", "The last WebTransport datagram received (empty when none)");
	ADD_API_FUNCTION(quic_error, "int", "", "The local or remote error code once closed");
	halt();
}
