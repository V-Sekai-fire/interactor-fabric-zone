cmake_minimum_required(VERSION 3.16)
project(interactor_fabric_zone C CXX)

# FZ_NATIVE builds the same libraries for the host, for the Lean tests (tests/) to link through
# their FFI shim. Otherwise this is the riscv64 guest build: the toolchain file comes from the
# riscv64 sysroot, and each guest links the vendored godot-sandbox API.
option(FZ_NATIVE "Build the libraries for the host, for the Lean tests" OFF)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
add_compile_options("-ffile-prefix-map=${CMAKE_SOURCE_DIR}/=")

if(NOT FZ_NATIVE)
	set(DOWNLOAD_RUNTIME_API OFF CACHE BOOL "" FORCE)
	add_subdirectory(vendor/sandbox-api/cmake sandbox_api)
endif()

include(cmake/fz_mbedtls.cmake)
if(NOT FZ_NATIVE)
	target_link_libraries(fz_mbedtls PUBLIC sandbox_api)
endif()

add_library(fz_ca STATIC src/ca/fz_ca.cpp src/ca/fz_entropy.cpp)
target_include_directories(fz_ca PUBLIC src/ca)
target_link_libraries(fz_ca PUBLIC fz_mbedtls)

include(cmake/fz_picoquic.cmake)
add_library(fz_quic STATIC src/transport/fz_quic.cpp)
target_include_directories(fz_quic PUBLIC src/transport)
target_link_libraries(fz_quic PUBLIC fz_picoquic fz_ca)

# The zone and casync assets (RFD 2287 steps 5 and 6), ported from the fabric engine build's
# multiplayer_fabric and multiplayer_fabric_asset modules, with zstd, SQLite and r128 beside them.
# No assembly fast paths and no threads: the same code in the guest and on the host.
file(GLOB FZ_ZSTD_SOURCES thirdparty/zstd/common/*.c thirdparty/zstd/compress/*.c thirdparty/zstd/decompress/*.c)
add_library(fz_zone_third STATIC ${FZ_ZSTD_SOURCES} thirdparty/sqlite/sqlite3.c thirdparty/misc/r128.c)
target_include_directories(fz_zone_third PUBLIC thirdparty/zstd thirdparty/sqlite ${CMAKE_SOURCE_DIR})
target_compile_definitions(fz_zone_third PUBLIC ZSTD_DISABLE_ASM SQLITE_THREADSAFE=0 SQLITE_OMIT_LOAD_EXTENSION
	SQLITE_DEFAULT_MEMSTATUS=0)
add_library(fz_zone STATIC src/transport/loopback.cpp src/transport/frame_transport.cpp src/casync/casync.cpp
	src/zone/zone_core.cpp src/zone/zone.cpp src/zone/pose.cpp src/zone/journal.cpp)
target_include_directories(fz_zone PUBLIC src ${CMAKE_SOURCE_DIR})
target_link_libraries(fz_zone PUBLIC fz_zone_third)

if(NOT FZ_NATIVE)
	function(add_guest name)
		add_sandbox_program(${name} ${ARGN})
		target_link_libraries(${name} PRIVATE -lstdc++ -lm)
		add_custom_command(TARGET ${name} POST_BUILD
			COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:${name}> ${CMAKE_SOURCE_DIR}/project/${name}.elf
			COMMENT "Installing ${name}.elf into project/")
	endfunction()

	add_guest(ca guest/ca/main.cpp)
	target_link_libraries(ca PRIVATE fz_ca)

	add_guest(quic_peer guest/quic_peer/main.cpp)
	target_link_libraries(quic_peer PRIVATE fz_quic)

	add_guest(zone guest/zone/main.cpp)
	target_link_libraries(zone PRIVATE fz_zone)

	add_guest(asset guest/asset/main.cpp)
	target_link_libraries(asset PRIVATE fz_zone)
endif()
