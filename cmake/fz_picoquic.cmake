# picoquic (with picohttp's h3zero and WebTransport) and picotls on mbedTLS, as the fabric build's
# modules/http3/SCsub compiles them: no OpenSSL, no x86-only cipher code, no minicrypto.
set(FZ_PICOQUIC ${CMAKE_CURRENT_LIST_DIR}/../thirdparty/picoquic)
set(FZ_PICOTLS ${CMAKE_CURRENT_LIST_DIR}/../thirdparty/picotls)

file(GLOB FZ_PICOQUIC_SOURCES ${FZ_PICOQUIC}/picoquic/*.c ${FZ_PICOQUIC}/picohttp/*.c ${FZ_PICOQUIC}/picoquic_mbedtls/*.c)
list(FILTER FZ_PICOQUIC_SOURCES EXCLUDE REGEX "picoquic_ptls_(openssl|fusion|minicrypto)\\.c$|winsockloop\\.c$")

add_library(fz_picoquic STATIC ${FZ_PICOQUIC_SOURCES}
	${FZ_PICOTLS}/lib/picotls.c ${FZ_PICOTLS}/lib/pembase64.c ${FZ_PICOTLS}/lib/hpke.c ${FZ_PICOTLS}/lib/asn1.c)
target_compile_definitions(fz_picoquic PUBLIC PTLS_WITHOUT_OPENSSL PTLS_WITHOUT_FUSION PICOQUIC_WITH_MBEDTLS
	DISABLE_DEBUG_PRINTF)
target_include_directories(fz_picoquic PUBLIC ${FZ_PICOTLS}/include ${FZ_PICOQUIC}/picoquic ${FZ_PICOQUIC}/picohttp
	${FZ_PICOQUIC}/picoquic_mbedtls)
target_link_libraries(fz_picoquic PUBLIC fz_mbedtls)
target_compile_options(fz_picoquic PRIVATE -w)
# mbedTLS 4 dropped this macro; without it the glue compiles out its SEC1 "EC PRIVATE KEY" reader.
target_compile_definitions(fz_picoquic PRIVATE MBEDTLS_PK_HAVE_ECC_KEYS)
