// SPDX-FileCopyrightText: 2026 K. S. Ernest (iFire) Lee
// SPDX-License-Identifier: MIT
// The macOS half: a non-permanent Secure Enclave P-256 key, kept as its token handle in DIR/se.handle.
#include "fz_seal.h"

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <string>

namespace fz_seal {
namespace {

// kSecAttrTokenOID, the attribute that carries an Enclave key's handle; the public SDK headers omit it.
const CFStringRef kTokenObjectId = CFSTR("toid");
const char *const kHandleName = "se.handle";
const size_t kHandleMax = 4096;
const size_t kPointBytes = 65;
const CFStringRef kTokenErrorDomain = CFSTR("CryptoTokenKit");
const long kTokenCanceledByUser = -4;
const CFStringRef kAuthenticationErrorDomain = CFSTR("com.apple.LocalAuthentication");
const long kAuthenticationUserCancel = -2;

template <typename T>
class CfRef {
public:
	explicit CfRef(T p_ref = nullptr) :
			ref(p_ref) {}
	~CfRef() {
		if (ref != nullptr) {
			CFRelease(ref);
		}
	}
	CfRef(const CfRef &) = delete;
	CfRef &operator=(const CfRef &) = delete;
	T get() const { return ref; }
	explicit operator bool() const { return ref != nullptr; }

private:
	T ref;
};

CFMutableDictionaryRef new_dictionary() {
	return CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks,
			&kCFTypeDictionaryValueCallBacks);
}

long error_code(CFErrorRef p_error) {
	return p_error == nullptr ? 0 : long(CFErrorGetCode(p_error));
}

bool cancelled(CFErrorRef p_error) {
	if (p_error == nullptr) {
		return false;
	}
	CFStringRef domain = CFErrorGetDomain(p_error);
	long code = error_code(p_error);
	return code == errSecUserCanceled || (code == kTokenCanceledByUser && CFEqual(domain, kTokenErrorDomain)) ||
			(code == kAuthenticationUserCancel && CFEqual(domain, kAuthenticationErrorDomain));
}

void error_text(CFErrorRef p_error, char *r_text, size_t p_size) {
	r_text[0] = '\0';
	if (p_error == nullptr) {
		return;
	}
	CfRef<CFStringRef> description(CFErrorCopyDescription(p_error));
	if (description) {
		CFStringGetCString(description.get(), r_text, CFIndex(p_size), kCFStringEncodingUTF8);
	}
}

// Takes ownership of p_error.
int fail_error(int p_status, const char *p_what, CFErrorRef p_error) {
	char text[512];
	error_text(p_error, text, sizeof text);
	fprintf(stderr, "fz_seal: %s (%ld %s)\n", p_what, error_code(p_error), text);
	if (p_error != nullptr) {
		CFRelease(p_error);
	}
	return p_status;
}

SecKeyRef create_enclave_key(bool p_presence, CFErrorRef *r_error) {
	SecAccessControlCreateFlags flags = kSecAccessControlPrivateKeyUsage;
	if (p_presence) {
		flags |= kSecAccessControlUserPresence;
	}
	CfRef<SecAccessControlRef> access(SecAccessControlCreateWithFlags(kCFAllocatorDefault,
			kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, r_error));
	if (!access) {
		return nullptr;
	}
	CfRef<CFMutableDictionaryRef> private_attributes(new_dictionary());
	CFDictionarySetValue(private_attributes.get(), kSecAttrIsPermanent, kCFBooleanFalse);
	CFDictionarySetValue(private_attributes.get(), kSecAttrAccessControl, access.get());
	int bits = 256;
	CfRef<CFNumberRef> size(CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &bits));
	CfRef<CFMutableDictionaryRef> attributes(new_dictionary());
	CFDictionarySetValue(attributes.get(), kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
	CFDictionarySetValue(attributes.get(), kSecAttrKeySizeInBits, size.get());
	CFDictionarySetValue(attributes.get(), kSecAttrTokenID, kSecAttrTokenIDSecureEnclave);
	CFDictionarySetValue(attributes.get(), kSecPrivateKeyAttrs, private_attributes.get());
	return SecKeyCreateRandomKey(attributes.get(), r_error);
}

SecKeyRef restore_enclave_key(const Bytes &p_handle, CFErrorRef *r_error) {
	CfRef<CFDataRef> handle(CFDataCreate(kCFAllocatorDefault, p_handle.data(), CFIndex(p_handle.size())));
	CfRef<CFDataRef> empty(CFDataCreate(kCFAllocatorDefault, nullptr, 0));
	CfRef<CFMutableDictionaryRef> attributes(new_dictionary());
	CFDictionarySetValue(attributes.get(), kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
	CFDictionarySetValue(attributes.get(), kSecAttrKeyClass, kSecAttrKeyClassPrivate);
	CFDictionarySetValue(attributes.get(), kSecAttrTokenID, kSecAttrTokenIDSecureEnclave);
	CFDictionarySetValue(attributes.get(), kTokenObjectId, handle.get());
	return SecKeyCreateWithData(empty.get(), attributes.get(), r_error);
}

SecKeyRef import_public_point(const Bytes &p_point, CFErrorRef *r_error) {
	CfRef<CFDataRef> point(CFDataCreate(kCFAllocatorDefault, p_point.data(), CFIndex(p_point.size())));
	CfRef<CFMutableDictionaryRef> attributes(new_dictionary());
	CFDictionarySetValue(attributes.get(), kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
	CFDictionarySetValue(attributes.get(), kSecAttrKeyClass, kSecAttrKeyClassPublic);
	return SecKeyCreateWithData(point.get(), attributes.get(), r_error);
}

bool public_point(SecKeyRef p_key, Bytes &r_point) {
	CfRef<SecKeyRef> public_key(SecKeyCopyPublicKey(p_key));
	if (!public_key) {
		return false;
	}
	CfRef<CFDataRef> data(SecKeyCopyExternalRepresentation(public_key.get(), nullptr));
	if (!data || CFDataGetLength(data.get()) != CFIndex(kPointBytes)) {
		return false;
	}
	r_point.assign(CFDataGetBytePtr(data.get()), CFDataGetBytePtr(data.get()) + kPointBytes);
	return true;
}

std::string handle_path(const char *p_dir) {
	return std::string(p_dir) + "/" + kHandleName;
}

int read_handle(const char *p_dir, Bytes &r_handle) {
	int fd = open(handle_path(p_dir).c_str(), O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		return errno == ENOENT ? fail(STATUS_NOT_FOUND, "no se.handle in the store") : fail_code(STATUS_IO, "open se.handle", errno);
	}
	r_handle.resize(kHandleMax + 1);
	size_t got = 0;
	ssize_t n = 0;
	while (got < r_handle.size() && (n = read(fd, r_handle.data() + got, r_handle.size() - got)) > 0) {
		got += size_t(n);
	}
	close(fd);
	if (n < 0 || got == 0 || got > kHandleMax) {
		wipe(r_handle);
		return fail(STATUS_IO, "se.handle is unreadable or the wrong size");
	}
	r_handle.resize(got);
	return STATUS_OK;
}

// Written beside the target, flushed, then linked in, so an existing handle is never replaced.
int write_new_file(const char *p_dir, const char *p_name, const Bytes &p_bytes) {
	std::string target = std::string(p_dir) + "/" + p_name;
	std::string temporary = std::string(p_dir) + "/." + p_name + "." + std::to_string(long(getpid())) + ".tmp";
	int fd = open(temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	if (fd < 0) {
		return fail_code(STATUS_IO, "create the temporary handle file", errno);
	}
	size_t put = 0;
	ssize_t n = 0;
	while (put < p_bytes.size() && (n = write(fd, p_bytes.data() + put, p_bytes.size() - put)) > 0) {
		put += size_t(n);
	}
	bool written = put == p_bytes.size() && fsync(fd) == 0;
	written = close(fd) == 0 && written;
	int linked = written ? link(temporary.c_str(), target.c_str()) : -1;
	int link_errno = errno;
	unlink(temporary.c_str());
	if (!written) {
		return fail(STATUS_IO, "write the temporary handle file");
	}
	if (linked != 0) {
		return link_errno == EEXIST ? fail(STATUS_EXISTS, "se.handle exists; it is never replaced")
									: fail_code(STATUS_IO, "link se.handle", link_errno);
	}
	int dir_fd = open(p_dir, O_RDONLY | O_CLOEXEC);
	if (dir_fd >= 0) {
		fsync(dir_fd);
		close(dir_fd);
	}
	return STATUS_OK;
}

int verb_probe() {
	CFErrorRef error = nullptr;
	SecKeyRef key = create_enclave_key(false, &error);
	if (key == nullptr) {
		char text[512];
		error_text(error, text, sizeof text);
		printf("secure-enclave unavailable (%ld %s)\n", error_code(error), text);
		if (error != nullptr) {
			CFRelease(error);
		}
		return STATUS_UNAVAILABLE;
	}
	CFRelease(key);
	puts("secure-enclave available");
	return STATUS_OK;
}

int verb_create(const char *p_dir, bool p_presence) {
	struct stat existing;
	if (stat(handle_path(p_dir).c_str(), &existing) == 0) {
		return fail(STATUS_EXISTS, "se.handle exists; it is never replaced");
	}
	CFErrorRef error = nullptr;
	CfRef<SecKeyRef> key(create_enclave_key(p_presence, &error));
	if (!key) {
		return fail_error(STATUS_UNAVAILABLE, "secure-enclave unavailable", error);
	}
	CfRef<CFDictionaryRef> attributes(SecKeyCopyAttributes(key.get()));
	CFTypeRef handle_value = attributes ? CFDictionaryGetValue(attributes.get(), kTokenObjectId) : nullptr;
	if (handle_value == nullptr || CFGetTypeID(handle_value) != CFDataGetTypeID()) {
		return fail(STATUS_UNAVAILABLE, "the Enclave key carries no token handle");
	}
	CFDataRef handle_data = static_cast<CFDataRef>(handle_value);
	Bytes handle(CFDataGetBytePtr(handle_data), CFDataGetBytePtr(handle_data) + CFDataGetLength(handle_data));
	Bytes point;
	if (!public_point(key.get(), point)) {
		return fail(STATUS_UNAVAILABLE, "the Enclave key has no P-256 public point");
	}
	int status = write_new_file(p_dir, kHandleName, handle);
	wipe(handle);
	if (status != STATUS_OK) {
		return status;
	}
	return write_hex_line(point.data(), point.size()) ? STATUS_OK : fail(STATUS_IO, "write the public key");
}

int verb_public(const char *p_dir) {
	Bytes handle;
	int status = read_handle(p_dir, handle);
	if (status != STATUS_OK) {
		return status;
	}
	CFErrorRef error = nullptr;
	CfRef<SecKeyRef> key(restore_enclave_key(handle, &error));
	wipe(handle);
	if (!key) {
		return fail_error(STATUS_REFUSED, "the Enclave refused se.handle", error);
	}
	Bytes point;
	if (!public_point(key.get(), point)) {
		return fail(STATUS_REFUSED, "the Enclave key has no P-256 public point");
	}
	return write_hex_line(point.data(), point.size()) ? STATUS_OK : fail(STATUS_IO, "write the public key");
}

int verb_z(const char *p_dir) {
	Bytes enc;
	if (!read_hex_line(enc, kPointBytes) || enc.size() != kPointBytes || enc[0] != 4) {
		return fail(STATUS_INPUT, "expected enc as one line of 65-byte SEC1 hex on stdin");
	}
	Bytes handle;
	int status = read_handle(p_dir, handle);
	if (status != STATUS_OK) {
		return status;
	}
	CFErrorRef error = nullptr;
	CfRef<SecKeyRef> key(restore_enclave_key(handle, &error));
	wipe(handle);
	if (!key) {
		return fail_error(STATUS_REFUSED, "the Enclave refused se.handle", error);
	}
	CfRef<SecKeyRef> peer(import_public_point(enc, &error));
	if (!peer) {
		return fail_error(STATUS_INPUT, "enc is not a P-256 point", error);
	}
	CfRef<CFDictionaryRef> parameters(CFDictionaryCreate(kCFAllocatorDefault, nullptr, nullptr, 0,
			&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks));
	CfRef<CFDataRef> shared(SecKeyCopyKeyExchangeResult(key.get(), kSecKeyAlgorithmECDHKeyExchangeStandard, peer.get(),
			parameters.get(), &error));
	if (!shared) {
		int status_code = cancelled(error) ? STATUS_CANCELLED : STATUS_REFUSED;
		return fail_error(status_code, "the Enclave refused the key agreement", error);
	}
	Bytes z(CFDataGetBytePtr(shared.get()), CFDataGetBytePtr(shared.get()) + CFDataGetLength(shared.get()));
	bool written = z.size() == 32 && write_hex_line(z.data(), z.size());
	wipe(z);
	return written ? STATUS_OK : fail(STATUS_IO, "write Z");
}

} // namespace

const char *platform_usage() {
	return "usage: fz_seal probe\n"
		   "       fz_seal create DIR [--no-presence]   make the Enclave key, write DIR/se.handle, print its public key\n"
		   "       fz_seal public DIR                   print the public key of DIR/se.handle\n"
		   "       fz_seal z DIR                        enc hex on stdin, the ECDH shared secret Z hex on stdout\n";
}

int platform_main(int p_argc, char **p_argv) {
	const char *verb = p_argv[1];
	if (p_argc == 2 && strcmp(verb, "probe") == 0) {
		return verb_probe();
	}
	if (strcmp(verb, "create") == 0 && (p_argc == 3 || (p_argc == 4 && strcmp(p_argv[3], "--no-presence") == 0))) {
		return verb_create(p_argv[2], p_argc == 3);
	}
	if (p_argc == 3 && strcmp(verb, "public") == 0) {
		return verb_public(p_argv[2]);
	}
	if (p_argc == 3 && strcmp(verb, "z") == 0) {
		return verb_z(p_argv[2]);
	}
	fputs(platform_usage(), stderr);
	return STATUS_USAGE;
}

} // namespace fz_seal
