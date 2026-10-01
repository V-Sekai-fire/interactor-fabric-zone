# mbedTLS 4 as the guests use it: the crypto core, X.509 parse and write, no TLS module.
# The source list follows the fabric build's modules/mbedtls/SCsub.
set(FZ_MBEDTLS ${CMAKE_CURRENT_LIST_DIR}/../thirdparty/mbedtls)
set(FZ_PSA ${FZ_MBEDTLS}/tf-psa-crypto)

set(FZ_PSA_SOURCES
	drivers/builtin/src/aes.c drivers/builtin/src/aria.c drivers/builtin/src/bignum.c
	drivers/builtin/src/bignum_core.c drivers/builtin/src/bignum_mod.c drivers/builtin/src/bignum_mod_raw.c
	drivers/builtin/src/block_cipher.c drivers/builtin/src/camellia.c drivers/builtin/src/ccm.c
	drivers/builtin/src/chacha20.c drivers/builtin/src/chacha20_neon.c drivers/builtin/src/chachapoly.c
	drivers/builtin/src/cipher.c
	drivers/builtin/src/cipher_wrap.c drivers/builtin/src/cmac.c drivers/builtin/src/ctr_drbg.c
	drivers/builtin/src/ecdsa.c drivers/builtin/src/ecjpake.c drivers/builtin/src/ecp.c
	drivers/builtin/src/ecp_curves.c drivers/builtin/src/ecp_curves_new.c drivers/builtin/src/entropy.c
	drivers/builtin/src/entropy_poll.c drivers/builtin/src/gcm.c drivers/builtin/src/hmac_drbg.c
	drivers/builtin/src/md5.c drivers/builtin/src/poly1305.c drivers/builtin/src/psa_crypto_aead.c
	drivers/builtin/src/psa_crypto_cipher.c drivers/builtin/src/psa_crypto_ecp.c drivers/builtin/src/psa_crypto_ffdh.c
	drivers/builtin/src/psa_crypto_hash.c drivers/builtin/src/psa_crypto_mac.c drivers/builtin/src/psa_crypto_pake.c
	drivers/builtin/src/psa_crypto_rsa.c drivers/builtin/src/psa_crypto_xof.c drivers/builtin/src/psa_util_internal.c
	drivers/builtin/src/ripemd160.c drivers/builtin/src/rsa.c drivers/builtin/src/rsa_alt_helpers.c
	drivers/builtin/src/sha1.c drivers/builtin/src/sha256.c drivers/builtin/src/sha3.c drivers/builtin/src/sha512.c
	extras/lmots.c extras/lms.c extras/md.c extras/nist_kw.c extras/pk.c extras/pk_ecc.c extras/pk_rsa.c
	extras/pk_wrap.c extras/pkparse.c extras/pkwrite.c
	platform/memory_buffer_alloc.c platform/platform.c platform/platform_util.c platform/threading.c
	utilities/asn1parse.c utilities/asn1write.c utilities/base64.c utilities/constant_time.c utilities/oid.c
	utilities/pem.c utilities/pkcs5.c
	core/psa_crypto.c core/psa_crypto_client.c core/psa_crypto_random.c core/psa_crypto_slot_management.c
	core/psa_crypto_storage.c core/psa_its_file.c core/psa_util.c core/tf_psa_crypto_config.c
	core/tf_psa_crypto_version.c core/psa_crypto_driver_wrappers_no_static.c)
list(TRANSFORM FZ_PSA_SOURCES PREPEND ${FZ_PSA}/)

set(FZ_X509_SOURCES
	library/error.c library/mbedtls_config.c library/x509.c library/x509_create.c library/x509_crl.c
	library/x509_crt.c library/x509_csr.c library/x509_oid.c library/x509write.c library/x509write_crt.c
	library/x509write_csr.c library/version.c)
list(TRANSFORM FZ_X509_SOURCES PREPEND ${FZ_MBEDTLS}/)

add_library(fz_mbedtls STATIC ${FZ_PSA_SOURCES} ${FZ_X509_SOURCES})
target_compile_definitions(fz_mbedtls PUBLIC
	TF_PSA_CRYPTO_CONFIG_FILE="fz_psa_config.h"
	MBEDTLS_CONFIG_FILE="fz_mbedtls_config.h"
	MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS)
target_include_directories(fz_mbedtls PUBLIC
	${CMAKE_CURRENT_LIST_DIR}/../src/mbedtls_config
	${FZ_MBEDTLS}/include ${FZ_PSA}/include ${FZ_PSA}/drivers/builtin/include)
target_include_directories(fz_mbedtls PRIVATE
	${FZ_MBEDTLS}/library ${FZ_PSA}/core ${FZ_PSA}/drivers/builtin/src ${FZ_PSA}/platform
	${FZ_PSA}/utilities ${FZ_PSA}/extras ${FZ_PSA}/dispatch)
target_compile_options(fz_mbedtls PRIVATE -w)
if(WIN32)
	target_link_libraries(fz_mbedtls PUBLIC ws2_32)
endif()
