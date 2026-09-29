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
endif()
