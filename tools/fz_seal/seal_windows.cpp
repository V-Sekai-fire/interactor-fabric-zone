// SPDX-FileCopyrightText: 2026 K. S. Ernest (iFire) Lee
// SPDX-License-Identifier: MIT
// The Windows half: an RSA-2048 decrypt-only key on the TPM's Platform Crypto Provider, DPAPI where no
// TPM is usable, and a read of the Credential Manager entry the old keyring tool wrote.
#include "fz_seal.h"

#include <windows.h>

#include <bcrypt.h>
#include <ncrypt.h>
#include <wincred.h>
#include <wincrypt.h>

#include <stdio.h>
#include <string.h>

#include <string>

namespace fz_seal {
namespace {

// mingw's ncrypt.h has no MS_PLATFORM_CRYPTO_PROVIDER.
const wchar_t *const kPlatformProvider = L"Microsoft Platform Crypto Provider";
const wchar_t *const kDpapiDescription = L"fabric-zone offline-ca-root";
const char kDpapiEntropy[] = "fabric-zone offline-ca-root v1";
const DWORD kRsaBits = 2048;
const size_t kRsaBytes = kRsaBits / 8;
const size_t kSecretMax = 64;
const size_t kDpapiBlobMax = 4096;

class Provider {
public:
	Provider() = default;
	~Provider() {
		if (handle != 0) {
			NCryptFreeObject(handle);
		}
	}
	Provider(const Provider &) = delete;
	Provider &operator=(const Provider &) = delete;
	SECURITY_STATUS open() { return NCryptOpenStorageProvider(&handle, kPlatformProvider, 0); }
	NCRYPT_PROV_HANDLE handle = 0;
};

class Key {
public:
	Key() = default;
	~Key() {
		if (handle != 0) {
			NCryptFreeObject(handle);
		}
	}
	Key(const Key &) = delete;
	Key &operator=(const Key &) = delete;
	NCRYPT_KEY_HANDLE handle = 0;
};

std::wstring widen(const char *p_text) {
	int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, p_text, -1, nullptr, 0);
	if (count <= 0) {
		return std::wstring();
	}
	std::wstring wide(size_t(count), L'\0');
	MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, p_text, -1, &wide[0], count);
	wide.resize(size_t(count - 1));
	return wide;
}

bool key_missing(SECURITY_STATUS p_status) {
	return p_status == NTE_BAD_KEYSET || p_status == NTE_NOT_FOUND;
}

int open_key(Provider &r_provider, Key &r_key, const char *p_name) {
	SECURITY_STATUS status = r_provider.open();
	if (status != ERROR_SUCCESS) {
		return fail_code(STATUS_UNAVAILABLE, "tpm-pcp unavailable", long(status));
	}
	std::wstring name = widen(p_name);
	if (name.empty()) {
		return fail(STATUS_USAGE, "the key name must be non-empty UTF-8");
	}
	status = NCryptOpenKey(r_provider.handle, &r_key.handle, name.c_str(), 0, NCRYPT_SILENT_FLAG);
	if (key_missing(status)) {
		return fail(STATUS_NOT_FOUND, "no TPM key by that name");
	}
	return status == ERROR_SUCCESS ? STATUS_OK : fail_code(STATUS_UNAVAILABLE, "open the TPM key", long(status));
}

int export_public(NCRYPT_KEY_HANDLE p_key) {
	DWORD need = 0;
	SECURITY_STATUS status = NCryptExportKey(p_key, 0, BCRYPT_RSAPUBLIC_BLOB, nullptr, nullptr, 0, &need, 0);
	if (status != ERROR_SUCCESS || need == 0) {
		return fail_code(STATUS_REFUSED, "export the public key", long(status));
	}
	Bytes blob(need);
	status = NCryptExportKey(p_key, 0, BCRYPT_RSAPUBLIC_BLOB, nullptr, blob.data(), need, &need, 0);
	if (status != ERROR_SUCCESS) {
		return fail_code(STATUS_REFUSED, "export the public key", long(status));
	}
	return write_hex_line(blob.data(), need) ? STATUS_OK : fail(STATUS_IO, "write the public key");
}

SECURITY_STATUS set_dword(NCRYPT_HANDLE p_key, const wchar_t *p_property, DWORD p_value) {
	return NCryptSetProperty(p_key, p_property, reinterpret_cast<PBYTE>(&p_value), sizeof p_value, 0);
}

int verb_probe() {
	Provider provider;
	SECURITY_STATUS status = provider.open();
	if (status == ERROR_SUCCESS) {
		status = NCryptIsAlgSupported(provider.handle, BCRYPT_RSA_ALGORITHM, 0);
	}
	if (status != ERROR_SUCCESS) {
		printf("tpm-pcp unavailable (0x%08lx)\n", static_cast<unsigned long>(status));
		return STATUS_UNAVAILABLE;
	}
	DWORD implementation = 0;
	DWORD got = 0;
	status = NCryptGetProperty(provider.handle, NCRYPT_IMPL_TYPE_PROPERTY, reinterpret_cast<PBYTE>(&implementation),
			sizeof implementation, &got, 0);
	if (status == ERROR_SUCCESS && (implementation & NCRYPT_IMPL_HARDWARE_FLAG) == 0) {
		printf("tpm-pcp unavailable (implementation 0x%08lx is not hardware)\n",
				static_cast<unsigned long>(implementation));
		return STATUS_UNAVAILABLE;
	}
	puts("tpm-pcp available");
	return STATUS_OK;
}

int verb_create(const char *p_name) {
	Provider provider;
	SECURITY_STATUS status = provider.open();
	if (status != ERROR_SUCCESS) {
		return fail_code(STATUS_UNAVAILABLE, "tpm-pcp unavailable", long(status));
	}
	std::wstring name = widen(p_name);
	if (name.empty()) {
		return fail(STATUS_USAGE, "the key name must be non-empty UTF-8");
	}
	Key existing;
	status = NCryptOpenKey(provider.handle, &existing.handle, name.c_str(), 0, NCRYPT_SILENT_FLAG);
	if (status == ERROR_SUCCESS) {
		return fail(STATUS_EXISTS, "a TPM key by that name exists; it is never replaced");
	}
	if (!key_missing(status)) {
		return fail_code(STATUS_UNAVAILABLE, "tpm-pcp unavailable", long(status));
	}
	Key key;
	status = NCryptCreatePersistedKey(provider.handle, &key.handle, BCRYPT_RSA_ALGORITHM, name.c_str(), 0, 0);
	if (status == NTE_EXISTS) {
		return fail(STATUS_EXISTS, "a TPM key by that name exists; it is never replaced");
	}
	if (status != ERROR_SUCCESS) {
		return fail_code(STATUS_UNAVAILABLE, "create the TPM key", long(status));
	}
	if ((status = set_dword(key.handle, NCRYPT_LENGTH_PROPERTY, kRsaBits)) != ERROR_SUCCESS ||
			(status = set_dword(key.handle, NCRYPT_KEY_USAGE_PROPERTY, NCRYPT_ALLOW_DECRYPT_FLAG)) != ERROR_SUCCESS ||
			(status = NCryptFinalizeKey(key.handle, NCRYPT_SILENT_FLAG)) != ERROR_SUCCESS) {
		return fail_code(STATUS_UNAVAILABLE, "finalize the TPM key", long(status));
	}
	int exported = export_public(key.handle);
	if (exported != STATUS_OK && NCryptDeleteKey(key.handle, 0) == ERROR_SUCCESS) {
		key.handle = 0;
	}
	return exported;
}

int verb_public(const char *p_name) {
	Provider provider;
	Key key;
	int status = open_key(provider, key, p_name);
	return status == STATUS_OK ? export_public(key.handle) : status;
}

int verb_unwrap(const char *p_name, const char *p_hash) {
	const wchar_t *algorithm = strcmp(p_hash, "sha256") == 0 ? BCRYPT_SHA256_ALGORITHM
			: strcmp(p_hash, "sha1") == 0						  ? BCRYPT_SHA1_ALGORITHM
																  : nullptr;
	if (algorithm == nullptr) {
		return fail(STATUS_USAGE, "the OAEP hash is sha256 or sha1");
	}
	Bytes sealed;
	if (!read_hex_line(sealed, kRsaBytes) || sealed.size() != kRsaBytes) {
		return fail(STATUS_INPUT, "expected one line of 256-byte RSA ciphertext hex on stdin");
	}
	Provider provider;
	Key key;
	int status = open_key(provider, key, p_name);
	if (status != STATUS_OK) {
		return status;
	}
	BCRYPT_OAEP_PADDING_INFO padding = { const_cast<LPWSTR>(algorithm), nullptr, 0 };
	Bytes plain(kRsaBytes);
	DWORD got = 0;
	SECURITY_STATUS result = NCryptDecrypt(key.handle, sealed.data(), DWORD(sealed.size()), &padding, plain.data(),
			DWORD(plain.size()), &got, NCRYPT_PAD_OAEP_FLAG | NCRYPT_SILENT_FLAG);
	if (result != ERROR_SUCCESS || got == 0 || got > kSecretMax) {
		wipe(plain);
		return fail_code(STATUS_REFUSED, "the TPM refused the ciphertext", long(result));
	}
	bool written = write_hex_line(plain.data(), got);
	wipe(plain);
	return written ? STATUS_OK : fail(STATUS_IO, "write the plaintext");
}

DATA_BLOB entropy_blob(Bytes &r_storage) {
	r_storage.assign(kDpapiEntropy, kDpapiEntropy + sizeof kDpapiEntropy - 1);
	DATA_BLOB blob = { DWORD(r_storage.size()), r_storage.data() };
	return blob;
}

int verb_protect() {
	Bytes plain;
	if (!read_hex_line(plain, kSecretMax)) {
		return fail(STATUS_INPUT, "expected one line of at most 64 bytes of hex on stdin");
	}
	Bytes entropy_storage;
	DATA_BLOB entropy = entropy_blob(entropy_storage);
	DATA_BLOB input = { DWORD(plain.size()), plain.data() };
	DATA_BLOB output = { 0, nullptr };
	BOOL ok = CryptProtectData(&input, kDpapiDescription, &entropy, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &output);
	wipe(plain);
	if (!ok) {
		return fail_code(STATUS_REFUSED, "CryptProtectData", long(GetLastError()));
	}
	bool written = write_hex_line(output.pbData, output.cbData);
	LocalFree(output.pbData);
	return written ? STATUS_OK : fail(STATUS_IO, "write the protected blob");
}

int verb_unprotect() {
	Bytes blob;
	if (!read_hex_line(blob, kDpapiBlobMax)) {
		return fail(STATUS_INPUT, "expected one line of DPAPI blob hex on stdin");
	}
	Bytes entropy_storage;
	DATA_BLOB entropy = entropy_blob(entropy_storage);
	DATA_BLOB input = { DWORD(blob.size()), blob.data() };
	DATA_BLOB output = { 0, nullptr };
	if (!CryptUnprotectData(&input, nullptr, &entropy, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &output)) {
		return fail_code(STATUS_REFUSED, "CryptUnprotectData refused the blob", long(GetLastError()));
	}
	bool written = output.cbData <= kSecretMax && write_hex_line(output.pbData, output.cbData);
	SecureZeroMemory(output.pbData, output.cbData);
	LocalFree(output.pbData);
	return written ? STATUS_OK : fail(STATUS_IO, "write the plaintext");
}

int verb_legacy_read(const char *p_target) {
	std::wstring target = widen(p_target);
	if (target.empty()) {
		return fail(STATUS_USAGE, "the target must be non-empty UTF-8");
	}
	PCREDENTIALW credential = nullptr;
	if (!CredReadW(target.c_str(), CRED_TYPE_GENERIC, 0, &credential)) {
		DWORD error = GetLastError();
		return error == ERROR_NOT_FOUND ? fail(STATUS_NOT_FOUND, "no generic credential by that target")
										: fail_code(STATUS_REFUSED, "CredReadW", long(error));
	}
	bool written = credential->CredentialBlobSize > 0 &&
			write_hex_line(credential->CredentialBlob, credential->CredentialBlobSize);
	if (credential->CredentialBlobSize > 0) {
		SecureZeroMemory(credential->CredentialBlob, credential->CredentialBlobSize);
	}
	CredFree(credential);
	return written ? STATUS_OK : fail(STATUS_IO, "the credential is empty or stdout failed");
}

int verb_delete_key(const char *p_name) {
	Provider provider;
	Key key;
	int status = open_key(provider, key, p_name);
	if (status != STATUS_OK) {
		return status;
	}
	SECURITY_STATUS result = NCryptDeleteKey(key.handle, 0);
	if (result != ERROR_SUCCESS) {
		return fail_code(STATUS_REFUSED, "NCryptDeleteKey", long(result));
	}
	key.handle = 0;
	return STATUS_OK;
}

} // namespace

const char *platform_usage() {
	return "usage: fz_seal probe\n"
		   "       fz_seal create NAME               make the TPM key NAME, print its BCRYPT_RSAPUBLIC_BLOB hex\n"
		   "       fz_seal public NAME               print the BCRYPT_RSAPUBLIC_BLOB hex of NAME\n"
		   "       fz_seal unwrap NAME sha256|sha1   RSA-OAEP ciphertext hex on stdin, plaintext hex on stdout\n"
		   "       fz_seal protect | unprotect       DPAPI (CurrentUser), hex on stdin to hex on stdout\n"
		   "       fz_seal legacy-read TARGET        the generic credential's blob, as hex on stdout\n"
		   "       fz_seal delete-key NAME           delete the TPM key NAME (CI throwaway keys only)\n";
}

int platform_main(int p_argc, char **p_argv) {
	const char *verb = p_argv[1];
	if (p_argc == 2 && strcmp(verb, "probe") == 0) {
		return verb_probe();
	}
	if (p_argc == 3 && strcmp(verb, "create") == 0) {
		return verb_create(p_argv[2]);
	}
	if (p_argc == 3 && strcmp(verb, "public") == 0) {
		return verb_public(p_argv[2]);
	}
	if (p_argc == 4 && strcmp(verb, "unwrap") == 0) {
		return verb_unwrap(p_argv[2], p_argv[3]);
	}
	if (p_argc == 2 && strcmp(verb, "protect") == 0) {
		return verb_protect();
	}
	if (p_argc == 2 && strcmp(verb, "unprotect") == 0) {
		return verb_unprotect();
	}
	if (p_argc == 3 && strcmp(verb, "legacy-read") == 0) {
		return verb_legacy_read(p_argv[2]);
	}
	if (p_argc == 3 && strcmp(verb, "delete-key") == 0) {
		return verb_delete_key(p_argv[2]);
	}
	fputs(platform_usage(), stderr);
	return STATUS_USAGE;
}

} // namespace fz_seal
