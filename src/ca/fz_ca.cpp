// SPDX-FileCopyrightText: 2026 K. S. Ernest (iFire) Lee
// SPDX-License-Identifier: MIT
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include "fz_ca.h"

#include <mbedtls/md.h>
#include <mbedtls/pk.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/x509_csr.h>
#include <psa/crypto.h>

#include <stdio.h>
#include <string.h>
#include <time.h>

struct fz_ca {
	mbedtls_svc_key_id_t key_id;
	mbedtls_pk_context pk;
	const char *subject;
	const char *suffix;
	char root_pem[4096];
};

struct fz_key {
	mbedtls_svc_key_id_t key_id;
	mbedtls_pk_context pk;
};

namespace {

const char *kRootSubject = "CN=fabric zone session root";
const char *kOfflineSubject = "CN=fabric zone offline root";

// RFC 9180 DHKEM(P-256, HKDF-SHA256): suite_id is "KEM" || I2OSP(0x0010, 2), and the P-256 order.
const uint8_t kHpkeVersion[] = { 'H', 'P', 'K', 'E', '-', 'v', '1' };
const uint8_t kSuiteId[] = { 'K', 'E', 'M', 0x00, 0x10 };
const uint8_t kP256Order[32] = { 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51 };

psa_key_attributes_t key_attributes(bool p_exportable) {
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&attributes, 256);
	psa_key_usage_t usage = PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_SIGN_MESSAGE;
	if (p_exportable) {
		usage |= PSA_KEY_USAGE_EXPORT;
	}
	psa_set_key_usage_flags(&attributes, usage);
	psa_set_key_algorithm(&attributes, PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_ANY_HASH));
	return attributes;
}

mbedtls_svc_key_id_t make_key(bool p_exportable) {
	psa_key_attributes_t attributes = key_attributes(p_exportable);
	mbedtls_svc_key_id_t id = MBEDTLS_SVC_KEY_ID_INIT;
	if (psa_generate_key(&attributes, &id) != PSA_SUCCESS) {
		return MBEDTLS_SVC_KEY_ID_INIT;
	}
	return id;
}

size_t append(uint8_t *r_out, size_t p_at, const void *p_bytes, size_t p_count) {
	memcpy(r_out + p_at, p_bytes, p_count);
	return p_at + p_count;
}

bool hkdf_extract(const uint8_t *p_ikm, size_t p_ikm_len, uint8_t r_prk[32]) {
	psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
	bool ok = psa_key_derivation_setup(&op, PSA_ALG_HKDF_EXTRACT(PSA_ALG_SHA_256)) == PSA_SUCCESS &&
			psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT, nullptr, 0) == PSA_SUCCESS &&
			psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SECRET, p_ikm, p_ikm_len) == PSA_SUCCESS &&
			psa_key_derivation_output_bytes(&op, r_prk, 32) == PSA_SUCCESS;
	psa_key_derivation_abort(&op);
	return ok;
}

bool hkdf_expand(const uint8_t p_prk[32], const uint8_t *p_info, size_t p_info_len, uint8_t *r_out, size_t p_len) {
	psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
	bool ok = psa_key_derivation_setup(&op, PSA_ALG_HKDF_EXPAND(PSA_ALG_SHA_256)) == PSA_SUCCESS &&
			psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SECRET, p_prk, 32) == PSA_SUCCESS &&
			psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO, p_info, p_info_len) == PSA_SUCCESS &&
			psa_key_derivation_output_bytes(&op, r_out, p_len) == PSA_SUCCESS;
	psa_key_derivation_abort(&op);
	return ok;
}

// RFC 9180 section 7.1.3 DeriveKeyPair for P-256: rejection sampling over LabeledExpand candidates.
bool derive_p256_scalar(const uint8_t *p_ikm, size_t p_ikm_len, uint8_t r_sk[32]) {
	static const uint8_t kDkpPrk[] = { 'd', 'k', 'p', '_', 'p', 'r', 'k' };
	static const uint8_t kCandidate[] = { 'c', 'a', 'n', 'd', 'i', 'd', 'a', 't', 'e' };
	uint8_t labeled_ikm[sizeof kHpkeVersion + sizeof kSuiteId + sizeof kDkpPrk + FZ_SEED_BYTES];
	size_t n = append(labeled_ikm, 0, kHpkeVersion, sizeof kHpkeVersion);
	n = append(labeled_ikm, n, kSuiteId, sizeof kSuiteId);
	n = append(labeled_ikm, n, kDkpPrk, sizeof kDkpPrk);
	n = append(labeled_ikm, n, p_ikm, p_ikm_len);
	uint8_t prk[32];
	bool found = false;
	if (hkdf_extract(labeled_ikm, n, prk)) {
		const uint8_t length[2] = { 0x00, 32 };
		uint8_t info[sizeof length + sizeof kHpkeVersion + sizeof kSuiteId + sizeof kCandidate + 1];
		size_t m = append(info, 0, length, sizeof length);
		m = append(info, m, kHpkeVersion, sizeof kHpkeVersion);
		m = append(info, m, kSuiteId, sizeof kSuiteId);
		m = append(info, m, kCandidate, sizeof kCandidate);
		for (int counter = 0; counter <= 255 && !found; ++counter) {
			info[m] = uint8_t(counter);
			if (!hkdf_expand(prk, info, m + 1, r_sk, 32)) {
				break;
			}
			bool zero = true;
			for (int i = 0; i < 32; ++i) {
				zero = zero && r_sk[i] == 0;
			}
			found = !zero && memcmp(r_sk, kP256Order, 32) < 0;
		}
	}
	mbedtls_platform_zeroize(labeled_ikm, sizeof labeled_ikm);
	mbedtls_platform_zeroize(prk, sizeof prk);
	return found;
}

mbedtls_svc_key_id_t derive_key(const unsigned char *p_seed, size_t p_seed_len) {
	if (p_seed == nullptr || p_seed_len != FZ_SEED_BYTES) {
		return MBEDTLS_SVC_KEY_ID_INIT;
	}
	uint8_t sk[32];
	mbedtls_svc_key_id_t id = MBEDTLS_SVC_KEY_ID_INIT;
	if (derive_p256_scalar(p_seed, p_seed_len, sk)) {
		psa_key_attributes_t attributes = key_attributes(false);
		if (psa_import_key(&attributes, sk, sizeof sk, &id) != PSA_SUCCESS) {
			id = MBEDTLS_SVC_KEY_ID_INIT;
		}
	}
	mbedtls_platform_zeroize(sk, sizeof sk);
	return id;
}

bool utc_stamp(int64_t p_unix, char *r_out) {
	time_t t = time_t(p_unix);
	struct tm tm_utc;
	if (gmtime_r(&t, &tm_utc) == nullptr) {
		return false;
	}
	return strftime(r_out, 16, "%Y%m%d%H%M%S", &tm_utc) == 14;
}

int64_t x509_to_unix(const mbedtls_x509_time &p_time) {
	struct tm tm_utc;
	memset(&tm_utc, 0, sizeof tm_utc);
	tm_utc.tm_year = p_time.year - 1900;
	tm_utc.tm_mon = p_time.mon - 1;
	tm_utc.tm_mday = p_time.day;
	tm_utc.tm_hour = p_time.hour;
	tm_utc.tm_min = p_time.min;
	tm_utc.tm_sec = p_time.sec;
	return int64_t(timegm(&tm_utc));
}

bool label_char(char p_c) {
	return (p_c >= 'a' && p_c <= 'z') || (p_c >= '0' && p_c <= '9') || p_c == '-';
}

int write_cert(mbedtls_x509write_cert *p_writer, char *r_out, size_t p_capacity) {
	int ret = mbedtls_x509write_crt_pem(p_writer, reinterpret_cast<unsigned char *>(r_out), p_capacity);
	if (ret != 0) {
		return ret == MBEDTLS_ERR_X509_BUFFER_TOO_SMALL ? FZ_ERR_BUFFER : FZ_ERR_CRYPTO;
	}
	return int(strlen(r_out));
}

int set_serial_and_validity(mbedtls_x509write_cert *p_writer, int64_t p_not_before, int64_t p_seconds) {
	unsigned char serial[16];
	if (psa_generate_random(serial, sizeof serial) != PSA_SUCCESS) {
		return FZ_ERR_CRYPTO;
	}
	serial[0] = (serial[0] & 0x7f) | 0x01;
	char from[16];
	char to[16];
	if (!utc_stamp(p_not_before, from) || !utc_stamp(p_not_before + p_seconds, to)) {
		return FZ_ERR_TTL;
	}
	if (mbedtls_x509write_crt_set_serial_raw(p_writer, serial, sizeof serial) != 0 ||
			mbedtls_x509write_crt_set_validity(p_writer, from, to) != 0) {
		return FZ_ERR_CRYPTO;
	}
	return 0;
}

int clear_time_flags(void *, mbedtls_x509_crt *, int, uint32_t *r_flags) {
	*r_flags &= ~uint32_t(MBEDTLS_X509_BADCERT_EXPIRED | MBEDTLS_X509_BADCERT_FUTURE);
	return 0;
}

// One DNS label of lowercase letters, digits and inner hyphens, then exactly p_suffix.
bool name_allowed(const char *p_name, const char *p_suffix) {
	if (p_name == nullptr) {
		return false;
	}
	size_t n = strlen(p_name);
	size_t suffix = strlen(p_suffix);
	if (n <= suffix || strcmp(p_name + n - suffix, p_suffix) != 0) {
		return false;
	}
	size_t label = n - suffix;
	if (label > 63 || p_name[0] == '-' || p_name[label - 1] == '-') {
		return false;
	}
	for (size_t i = 0; i < label; ++i) {
		if (!label_char(p_name[i])) {
			return false;
		}
	}
	return true;
}

fz_ca *new_ca(mbedtls_svc_key_id_t p_key, const char *p_subject, const char *p_suffix, int64_t p_not_before,
		int64_t p_seconds) {
	fz_ca *ca = new fz_ca;
	memset(ca->root_pem, 0, sizeof ca->root_pem);
	mbedtls_pk_init(&ca->pk);
	ca->key_id = p_key;
	ca->subject = p_subject;
	ca->suffix = p_suffix;
	if (mbedtls_svc_key_id_is_null(ca->key_id) || mbedtls_pk_wrap_psa(&ca->pk, ca->key_id) != 0) {
		fz_ca_free(ca);
		return nullptr;
	}
	mbedtls_x509write_cert writer;
	mbedtls_x509write_crt_init(&writer);
	mbedtls_x509write_crt_set_version(&writer, MBEDTLS_X509_CRT_VERSION_3);
	mbedtls_x509write_crt_set_md_alg(&writer, MBEDTLS_MD_SHA256);
	mbedtls_x509write_crt_set_subject_key(&writer, &ca->pk);
	mbedtls_x509write_crt_set_issuer_key(&writer, &ca->pk);
	bool ok = set_serial_and_validity(&writer, p_not_before, p_seconds) == 0 &&
			mbedtls_x509write_crt_set_subject_name(&writer, p_subject) == 0 &&
			mbedtls_x509write_crt_set_issuer_name(&writer, p_subject) == 0 &&
			mbedtls_x509write_crt_set_basic_constraints(&writer, 1, 0) == 0 &&
			mbedtls_x509write_crt_set_key_usage(&writer, MBEDTLS_X509_KU_KEY_CERT_SIGN | MBEDTLS_X509_KU_CRL_SIGN) == 0 &&
			write_cert(&writer, ca->root_pem, sizeof ca->root_pem) > 0;
	mbedtls_x509write_crt_free(&writer);
	if (!ok) {
		fz_ca_free(ca);
		return nullptr;
	}
	return ca;
}

} // namespace

extern "C" int fz_crypto_init(void) {
	return int(psa_crypto_init());
}

extern "C" int fz_name_allowed(const char *p_name) {
	return name_allowed(p_name, FZ_NAME_SUFFIX) ? 1 : 0;
}

extern "C" fz_ca *fz_ca_new(int64_t p_not_before, int64_t p_seconds) {
	return new_ca(make_key(false), kRootSubject, FZ_NAME_SUFFIX, p_not_before, p_seconds);
}

extern "C" fz_ca *fz_ca_new_seeded(const unsigned char *p_seed, size_t p_seed_len, int64_t p_not_before,
		int64_t p_seconds) {
	mbedtls_svc_key_id_t key = derive_key(p_seed, p_seed_len);
	if (mbedtls_svc_key_id_is_null(key)) {
		return nullptr;
	}
	return new_ca(key, kOfflineSubject, FZ_FDB_NAME_SUFFIX, p_not_before, p_seconds);
}

extern "C" void fz_ca_free(fz_ca *p_ca) {
	if (p_ca == nullptr) {
		return;
	}
	mbedtls_pk_free(&p_ca->pk);
	psa_destroy_key(p_ca->key_id);
	delete p_ca;
}

extern "C" int fz_ca_root_pem(const fz_ca *p_ca, char *r_out, size_t p_capacity) {
	size_t n = strlen(p_ca->root_pem);
	if (n + 1 > p_capacity) {
		return FZ_ERR_BUFFER;
	}
	memcpy(r_out, p_ca->root_pem, n + 1);
	return int(n);
}

// The root's public point, uncompressed, in lowercase hex (the RFC 9180 test vectors' form).
extern "C" int fz_ca_root_public_hex(const fz_ca *p_ca, char *r_out, size_t p_capacity) {
	uint8_t point[65];
	size_t length = 0;
	if (psa_export_public_key(p_ca->key_id, point, sizeof point, &length) != PSA_SUCCESS) {
		return FZ_ERR_CRYPTO;
	}
	if (length * 2 + 1 > p_capacity) {
		return FZ_ERR_BUFFER;
	}
	for (size_t i = 0; i < length; ++i) {
		snprintf(r_out + 2 * i, 3, "%02x", point[i]);
	}
	return int(length * 2);
}

// The root key's policy has no export usage; this returns the PSA status of trying anyway.
extern "C" int fz_ca_export_root_key(const fz_ca *p_ca) {
	unsigned char buffer[256];
	size_t length = 0;
	return int(psa_export_key(p_ca->key_id, buffer, sizeof buffer, &length));
}

extern "C" int fz_ca_issue(fz_ca *p_ca, const char *p_csr_pem, const char *p_name, int64_t p_not_before,
		int64_t p_seconds, char *r_out, size_t p_capacity) {
	if (!name_allowed(p_name, p_ca->suffix)) {
		return FZ_ERR_NAME;
	}
	if (p_seconds <= 0 || p_seconds > FZ_MAX_SECONDS) {
		return FZ_ERR_TTL;
	}
	mbedtls_x509_csr csr;
	mbedtls_x509_csr_init(&csr);
	if (mbedtls_x509_csr_parse(&csr, reinterpret_cast<const unsigned char *>(p_csr_pem), strlen(p_csr_pem) + 1) != 0) {
		mbedtls_x509_csr_free(&csr);
		return FZ_ERR_CSR;
	}
	const mbedtls_md_info_t *md = mbedtls_md_info_from_type(csr.sig_md);
	unsigned char hash[MBEDTLS_MD_MAX_SIZE];
	if (md == nullptr || mbedtls_md(md, csr.cri.p, csr.cri.len, hash) != 0 ||
			mbedtls_pk_verify(&csr.pk, csr.sig_md, hash, mbedtls_md_get_size(md), csr.sig.p, csr.sig.len) != 0) {
		mbedtls_x509_csr_free(&csr);
		return FZ_ERR_CSR_SIGNATURE;
	}
	char subject[128];
	snprintf(subject, sizeof subject, "CN=%s", p_name);
	mbedtls_x509_san_list san;
	memset(&san, 0, sizeof san);
	san.node.type = MBEDTLS_X509_SAN_DNS_NAME;
	san.node.san.unstructured_name.p = reinterpret_cast<unsigned char *>(const_cast<char *>(p_name));
	san.node.san.unstructured_name.len = strlen(p_name);
	san.next = nullptr;

	mbedtls_x509write_cert writer;
	mbedtls_x509write_crt_init(&writer);
	mbedtls_x509write_crt_set_version(&writer, MBEDTLS_X509_CRT_VERSION_3);
	mbedtls_x509write_crt_set_md_alg(&writer, MBEDTLS_MD_SHA256);
	mbedtls_x509write_crt_set_subject_key(&writer, &csr.pk);
	mbedtls_x509write_crt_set_issuer_key(&writer, &p_ca->pk);
	int ret = set_serial_and_validity(&writer, p_not_before, p_seconds);
	if (ret == 0) {
		bool ok = mbedtls_x509write_crt_set_subject_name(&writer, subject) == 0 &&
				mbedtls_x509write_crt_set_issuer_name(&writer, p_ca->subject) == 0 &&
				mbedtls_x509write_crt_set_basic_constraints(&writer, 0, -1) == 0 &&
				mbedtls_x509write_crt_set_key_usage(&writer, MBEDTLS_X509_KU_DIGITAL_SIGNATURE) == 0 &&
				mbedtls_x509write_crt_set_subject_alternative_name(&writer, &san) == 0;
		ret = ok ? write_cert(&writer, r_out, p_capacity) : FZ_ERR_CRYPTO;
	}
	mbedtls_x509write_crt_free(&writer);
	mbedtls_x509_csr_free(&csr);
	return ret;
}

extern "C" fz_key *fz_key_new(void) {
	fz_key *key = new fz_key;
	mbedtls_pk_init(&key->pk);
	key->key_id = make_key(true);
	if (mbedtls_svc_key_id_is_null(key->key_id) || mbedtls_pk_wrap_psa(&key->pk, key->key_id) != 0) {
		fz_key_free(key);
		return nullptr;
	}
	return key;
}

extern "C" void fz_key_free(fz_key *p_key) {
	if (p_key == nullptr) {
		return;
	}
	mbedtls_pk_free(&p_key->pk);
	psa_destroy_key(p_key->key_id);
	delete p_key;
}

extern "C" int fz_key_csr_pem(fz_key *p_key, const char *p_name, char *r_out, size_t p_capacity) {
	char subject[128];
	snprintf(subject, sizeof subject, "CN=%s", p_name);
	mbedtls_x509write_csr writer;
	mbedtls_x509write_csr_init(&writer);
	mbedtls_x509write_csr_set_md_alg(&writer, MBEDTLS_MD_SHA256);
	mbedtls_x509write_csr_set_key(&writer, &p_key->pk);
	int ret = mbedtls_x509write_csr_set_subject_name(&writer, subject);
	if (ret == 0) {
		ret = mbedtls_x509write_csr_pem(&writer, reinterpret_cast<unsigned char *>(r_out), p_capacity);
	}
	mbedtls_x509write_csr_free(&writer);
	if (ret != 0) {
		return FZ_ERR_CRYPTO;
	}
	return int(strlen(r_out));
}

extern "C" int fz_key_pem(fz_key *p_key, char *r_out, size_t p_capacity) {
	mbedtls_pk_context copy;
	mbedtls_pk_init(&copy);
	int ret = mbedtls_pk_copy_from_psa(p_key->key_id, &copy);
	if (ret == 0) {
		ret = mbedtls_pk_write_key_pem(&copy, reinterpret_cast<unsigned char *>(r_out), p_capacity);
	}
	mbedtls_pk_free(&copy);
	if (ret != 0) {
		return FZ_ERR_CRYPTO;
	}
	return int(strlen(r_out));
}

// 0 when p_cert_pem chains to p_root_pem, names p_expected_name and is valid at p_now; else FZ_BAD_* bits.
extern "C" int fz_verify(const char *p_root_pem, const char *p_cert_pem, const char *p_expected_name, int64_t p_now) {
	mbedtls_x509_crt root;
	mbedtls_x509_crt cert;
	mbedtls_x509_crt_init(&root);
	mbedtls_x509_crt_init(&cert);
	int result = 0;
	if (mbedtls_x509_crt_parse(&root, reinterpret_cast<const unsigned char *>(p_root_pem), strlen(p_root_pem) + 1) != 0 ||
			mbedtls_x509_crt_parse(&cert, reinterpret_cast<const unsigned char *>(p_cert_pem), strlen(p_cert_pem) + 1) != 0) {
		result = FZ_BAD_PARSE;
	} else {
		uint32_t flags = 0;
		mbedtls_x509_crt_verify(&cert, &root, nullptr, p_expected_name, &flags, clear_time_flags, nullptr);
		if ((flags & MBEDTLS_X509_BADCERT_CN_MISMATCH) != 0) {
			result |= FZ_BAD_NAME;
		}
		if ((flags & ~uint32_t(MBEDTLS_X509_BADCERT_CN_MISMATCH)) != 0) {
			result |= FZ_BAD_CHAIN;
		}
		const mbedtls_x509_crt *checked[2] = { &cert, &root };
		for (const mbedtls_x509_crt *c : checked) {
			if (p_now > x509_to_unix(c->valid_to)) {
				result |= FZ_EXPIRED;
			}
			if (p_now < x509_to_unix(c->valid_from)) {
				result |= FZ_NOT_YET_VALID;
			}
		}
	}
	mbedtls_x509_crt_free(&cert);
	mbedtls_x509_crt_free(&root);
	return result;
}
