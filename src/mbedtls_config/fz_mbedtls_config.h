// SPDX-FileCopyrightText: 2026 K. S. Ernest (iFire) Lee
// SPDX-License-Identifier: MIT
// X.509 only: the guests do TLS through picotls, so mbedTLS's own TLS, sockets and timers are out.
#pragma once
#include <mbedtls/mbedtls_config.h>

#undef MBEDTLS_NET_C
#undef MBEDTLS_TIMING_C
#undef MBEDTLS_SSL_TLS_C
#undef MBEDTLS_SSL_CLI_C
#undef MBEDTLS_SSL_SRV_C
#undef MBEDTLS_SSL_COOKIE_C
#undef MBEDTLS_SSL_TICKET_C
#undef MBEDTLS_SSL_CACHE_C
#undef MBEDTLS_SSL_PROTO_TLS1_2
#undef MBEDTLS_SSL_PROTO_TLS1_3
#undef MBEDTLS_SSL_PROTO_DTLS
#undef MBEDTLS_SSL_DTLS_ANTI_REPLAY
#undef MBEDTLS_SSL_DTLS_HELLO_VERIFY
#undef MBEDTLS_SSL_DTLS_CLIENT_PORT_REUSE
#undef MBEDTLS_SSL_DTLS_CONNECTION_ID
#undef MBEDTLS_DEBUG_C
