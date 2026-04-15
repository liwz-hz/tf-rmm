# SPDX-License-Identifier: BSD-3-Clause
# SPDX-FileCopyrightText: Copyright TF-RMM Contributors.
#
# FindRustSpdm.cmake - Build and link rust-spdm-minimal library
#
# This module builds the rust-spdm-minimal static library using cargo
# and creates CMake targets for linking.
#
# Usage:
#   include(FindRustSpdm)
#   target_link_libraries(my_target PRIVATE rust-spdm-minimal)
#

if(RUST_SPDM_MINIMAL_FOUND)
    return()
endif()

# Find cargo executable
find_program(CARGO_EXECUTABLE cargo)
if(NOT CARGO_EXECUTABLE)
    message(FATAL_ERROR "cargo not found - required to build rust-spdm-minimal")
endif()

# Set paths
set(RUST_SPDM_DIR "${RMM_SOURCE_DIR}/rust-spdm-minimal")
set(RUST_SPDM_STATIC_LIB "${RUST_SPDM_DIR}/target/release/librust_spdm_minimal.a")
set(RUST_SPDM_HEADER "${RUST_SPDM_DIR}/include/rust_spdm.h")

# Build type mapping
if(CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL "")
    set(RUST_BUILD_TYPE "debug")
else()
    set(RUST_BUILD_TYPE "release")
endif()

# Detect target architecture for Rust
if(RMM_ARCH STREQUAL aarch64)
    if(CMAKE_CROSSCOMPILING)
        set(RUST_TARGET "aarch64-unknown-none")  # no_std target
    else()
        set(RUST_TARGET "aarch64-unknown-linux-gnu")
    endif()
elseif(RMM_ARCH STREQUAL fake_host)
    # Build for host architecture
    execute_process(
        COMMAND ${CARGO_EXECUTABLE} rustc -- --print cfg
        OUTPUT_VARIABLE RUST_HOST_CFG
        RESULT_VARIABLE RUST_CFG_RESULT
    )
    if(RUST_CFG_RESULT EQUAL 0 AND RUST_HOST_CFG MATCHES "target_arch=\"(x86_64|aarch64)\"")
        string(REGEX MATCH "target_arch=\"([^\"]+)\"" _MATCH "${RUST_HOST_CFG}")
        set(RUST_TARGET_ARCH "${CMAKE_MATCH_1}")
    else()
        # Fallback to host detection
        set(RUST_TARGET_ARCH "${CMAKE_HOST_SYSTEM_PROCESSOR}")
    endif()
endif()

# Build rust-spdm-minimal staticlib
add_custom_command(
    OUTPUT "${RUST_SPDM_STATIC_LIB}"
    COMMAND ${CMAKE_COMMAND} -E make_directory "${RUST_SPDM_BUILD_DIR}"
    COMMAND ${CARGO_EXECUTABLE} build 
            --features ffi
            --release
    WORKING_DIRECTORY "${RUST_SPDM_DIR}"
    COMMENT "Building rust-spdm-minimal with cargo"
    VERBATIM
)

add_custom_target(rust-spdm-minimal-build
    DEPENDS "${RUST_SPDM_STATIC_LIB}"
)

# Create imported static library target
add_library(rust-spdm-minimal STATIC IMPORTED GLOBAL)
set_target_properties(rust-spdm-minimal PROPERTIES
    IMPORTED_LOCATION "${RUST_SPDM_STATIC_LIB}"
    INTERFACE_INCLUDE_DIRECTORIES "${RUST_SPDM_DIR}/include"
)

# Add dependency to ensure build happens before linking
add_dependencies(rust-spdm-minimal rust-spdm-minimal-build)

# System libraries needed by Rust (for std builds on fake_host)
if(RMM_ARCH STREQUAL fake_host)
    # Rust std requires these system libraries
    set_property(TARGET rust-spdm-minimal APPEND PROPERTY
        INTERFACE_LINK_LIBRARIES
            -lpthread
            -ldl
            -lm
    )
endif()

# Mark as found
set(RUST_SPDM_MINIMAL_FOUND TRUE)

# Provide status message
message(STATUS "rust-spdm-minimal configured: ${RUST_SPDM_STATIC_LIB}")