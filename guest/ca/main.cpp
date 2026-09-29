// SPDX-FileCopyrightText: 2026 K. S. Ernest (iFire) Lee
// SPDX-License-Identifier: MIT
// ca.elf: the session's certificate authority. Its root key is made in guest memory with no export
// usage; the host only ever receives the public root certificate and the certificates it issues.
#include <api.hpp>

#include "fz_ca.h"

#include <cstdint>
#include <string>
#include <vector>

namespace {

fz_ca *g_ca = nullptr;
char g_buffer[8192];

Variant text(const std::string &p_s) {
	return Variant(String(p_s));
}

const char *source_name(int p_source) {
	return p_source == FZ_ENTROPY_OS ? "os" : (p_source == FZ_ENTROPY_HOST ? "host" : "none");
}

// Flips one base64 digit in the last full line of a PEM body: the signature's tail, same length.
std::string tamper_signature(const std::string &p_pem) {
	std::string pem = p_pem;
	size_t end = pem.rfind("\n-----END");
	size_t start = pem.rfind('\n', end - 1);
	size_t at = end - 4;
	if (end == std::string::npos || start == std::string::npos || at <= start) {
		return pem;
	}
	pem[at] = pem[at] == 'A' ? 'B' : 'A';
	return pem;
}

std::string check(const char *p_what, bool p_ok) {
	return std::string(p_ok ? "PASS " : "FAIL ") + p_what + "\n";
}

} // namespace

static Variant ca_entropy_feed(PackedArray<uint8_t> p_bytes) {
	std::vector<uint8_t> bytes = p_bytes.fetch();
	int ret = fz_entropy_feed(bytes.data(), bytes.size());
	return text(ret == 0 ? "pool=" + std::to_string(fz_entropy_pool_left()) : "FAIL: pool full");
}

static Variant ca_entropy_force_host(bool p_on) {
	fz_entropy_force_host(p_on ? 1 : 0);
	return text(p_on ? "host only" : "os first");
}

static Variant ca_open(int64_t p_now, int64_t p_root_seconds) {
	if (g_ca != nullptr) {
		return text("FAIL: already open");
	}
	unsigned char probe[32];
	int source = fz_entropy_probe(probe);
	if (source < 0) {
		return text("FAIL: no entropy (the OS source failed and the host pool is empty)");
	}
	int status = fz_crypto_init();
	if (status != 0) {
		return text("FAIL: psa_crypto_init " + std::to_string(status));
	}
	g_ca = fz_ca_new(p_now - 300, p_root_seconds);
	if (g_ca == nullptr) {
		return text("FAIL: root key or certificate");
	}
	return text(std::string("ok entropy=") + source_name(source));
}

static Variant ca_root() {
	if (g_ca == nullptr || fz_ca_root_pem(g_ca, g_buffer, sizeof g_buffer) < 0) {
		return text("FAIL: not open");
	}
	return text(g_buffer);
}

static Variant ca_issue(String p_csr_pem, String p_name, int64_t p_not_before, int64_t p_seconds) {
	if (g_ca == nullptr) {
		return text("FAIL: not open");
	}
	std::string csr = p_csr_pem.utf8();
	std::string name = p_name.utf8();
	int ret = fz_ca_issue(g_ca, csr.c_str(), name.c_str(), p_not_before, p_seconds, g_buffer, sizeof g_buffer);
	return text(ret < 0 ? "FAIL: " + std::to_string(ret) : std::string(g_buffer));
}

static Variant ca_export_root_key() {
	return Variant(int64_t(g_ca == nullptr ? 0 : fz_ca_export_root_key(g_ca)));
}

// Every check and control of the Lean tests, run in the guest itself, one PASS or FAIL line each.
static Variant ca_selftest(int64_t p_now) {
	if (g_ca == nullptr) {
		return text("FAIL: not open");
	}
	std::string out;
	static char root[4096];
	static char other_root[4096];
	static char csr[4096];
	static char cert[4096];
	fz_ca_root_pem(g_ca, root, sizeof root);
	fz_ca *other = fz_ca_new(p_now - 300, 86400);
	fz_ca_root_pem(other, other_root, sizeof other_root);
	fz_key *key = fz_key_new();
	const char *name = "player-0.zone.fabric.internal";
	fz_key_csr_pem(key, name, csr, sizeof csr);

	int issued = fz_ca_issue(g_ca, csr, name, p_now - 60, 3600, cert, sizeof cert);
	out += check("issue a one-hour certificate", issued > 0);
	out += check("it verifies against the session root", fz_verify(root, cert, name, p_now) == 0);
	out += check("control: another CA's root refuses it", (fz_verify(other_root, cert, name, p_now) & FZ_BAD_CHAIN) != 0);
	out += check("control: another name is refused", (fz_verify(root, cert, "player-1.zone.fabric.internal", p_now) & FZ_BAD_NAME) != 0);

	static char expired[4096];
	fz_ca_issue(g_ca, csr, name, p_now - 120, 60, expired, sizeof expired);
	out += check("control: a one-minute certificate from two minutes ago is refused",
			(fz_verify(root, expired, name, p_now) & FZ_EXPIRED) != 0);
	out += check("the same certificate verifies inside its minute", fz_verify(root, expired, name, p_now - 90) == 0);

	out += check("control: a name outside the zone suffix is not issued",
			fz_ca_issue(g_ca, csr, "player-0.example.com", p_now, 60, cert, sizeof cert) == FZ_ERR_NAME);
	out += check("control: more than an hour is not issued",
			fz_ca_issue(g_ca, csr, name, p_now, FZ_MAX_SECONDS + 1, cert, sizeof cert) == FZ_ERR_TTL);
	std::string bad = tamper_signature(csr);
	out += check("control: a CSR with a broken signature is not issued",
			fz_ca_issue(g_ca, bad.c_str(), name, p_now, 60, cert, sizeof cert) == FZ_ERR_CSR_SIGNATURE);
	out += check("the root key refuses export", fz_ca_export_root_key(g_ca) != 0);

	fz_key_free(key);
	fz_ca_free(other);
	return text(std::string("entropy=") + source_name(fz_entropy_source()) + "\n" + out);
}

int main() {
	ADD_API_FUNCTION(ca_entropy_feed, "String", "PackedByteArray bytes", "Host-supplied entropy, used when the OS source fails");
	ADD_API_FUNCTION(ca_entropy_force_host, "String", "bool on", "Skip the OS source, to exercise the host fallback");
	ADD_API_FUNCTION(ca_open, "String", "int now, int root_seconds", "Make the session root key and certificate");
	ADD_API_FUNCTION(ca_root, "String", "", "The public root certificate, PEM");
	ADD_API_FUNCTION(ca_issue, "String", "String csr_pem, String name, int not_before, int seconds",
			"A certificate for a *.zone.fabric.internal name, at most an hour, PEM or FAIL: <code>");
	ADD_API_FUNCTION(ca_export_root_key, "int", "", "The PSA status of exporting the root key (must be an error)");
	ADD_API_FUNCTION(ca_selftest, "String", "int now", "The checks and their controls, in the guest");
	halt();
}
