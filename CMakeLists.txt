# Copyright 2024
#
# This file is part of gr-linux-crypto
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

cmake_minimum_required(VERSION 3.16)
if(POLICY CMP0057)
    cmake_policy(SET CMP0057 NEW)
endif()

project(gr-linux-crypto)

########################################################################
# Find dependencies
########################################################################
# Set CMAKE_MODULE_PATH to find GNU Radio CMake modules
# Search in common installation locations
list(APPEND CMAKE_MODULE_PATH
    /usr/local/lib/cmake/gnuradio
    /usr/lib/x86_64-linux-gnu/cmake/gnuradio
    /usr/lib/cmake/gnuradio
    ${CMAKE_INSTALL_PREFIX}/lib/cmake/gnuradio
)
include(GrBoost)

# Required dependencies
find_package(PkgConfig REQUIRED)
pkg_check_modules(KEYUTILS REQUIRED libkeyutils)

# Optional dependencies for integration
pkg_check_modules(OPENSSL QUIET openssl)
pkg_check_modules(SODIUM QUIET libsodium)

# Optional GPGME support for OpenPGP Card operations
pkg_check_modules(GPGME QUIET gpgme)

# Optional hardware security module support
# Try libnitrokey-1 first (actual package name), fall back to libnitrokey
pkg_check_modules(NITROKEY QUIET libnitrokey-1 libnitrokey)

########################################################################
# Register component
########################################################################
# Find GNU Radio via pkg-config first (sets ENABLE_GNURADIO_RUNTIME)
pkg_check_modules(GNURADIO_RUNTIME REQUIRED gnuradio-runtime)
if(GNURADIO_RUNTIME_FOUND)
    set(ENABLE_GNURADIO_RUNTIME ON)
    # Check for minimum GNU Radio version (3.10.12.0 or later)
    # This check ensures compatibility while allowing future versions
    set(GNURADIO_MIN_VERSION "3.10.12.0")
    if(DEFINED GNURADIO_RUNTIME_VERSION)
        if(GNURADIO_RUNTIME_VERSION VERSION_LESS GNURADIO_MIN_VERSION)
            message(FATAL_ERROR "GNU Radio version ${GNURADIO_MIN_VERSION} or later is required. Found: ${GNURADIO_RUNTIME_VERSION}")
        else()
            # Log version for compatibility tracking
            message(STATUS "GNU Radio version: ${GNURADIO_RUNTIME_VERSION} (minimum required: ${GNURADIO_MIN_VERSION})")
        endif()
    else()
        message(WARNING "GNU Radio version could not be determined. Please ensure GNU Radio ${GNURADIO_MIN_VERSION} or later is installed.")
    endif()
endif()

include(GrComponent)
gr_register_component("gr-linux-crypto" ENABLE_GR_LINUX_CRYPTO KEYUTILS_FOUND ENABLE_GNURADIO_RUNTIME)

########################################################################
# Build options
########################################################################
option(ENABLE_PYTHON "Enable Python bindings" ON)
option(ENABLE_GRC "Enable GRC block definitions" ON)
option(ENABLE_EXAMPLES "Install example scripts" ON)
option(ENABLE_DOXYGEN "Build Doxygen documentation" OFF)
option(ENABLE_TESTING "Enable testing" OFF)
option(ENABLE_FUZZING "Enable fuzzing targets" OFF)

########################################################################
# Begin conditional configuration
########################################################################
if(ENABLE_GR_LINUX_CRYPTO)

########################################################################
# Compiler setup
########################################################################
if(CMAKE_COMPILER_IS_GNUCXX AND NOT WIN32)
    add_definitions(-fvisibility=hidden)
endif()

########################################################################
# Include directories
########################################################################
include_directories(${CMAKE_SOURCE_DIR}/lib)
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${GNURADIO_INCLUDE_DIRS})

########################################################################
# API definition
# Note: LINUX_CRYPTO_API is defined in include/gnuradio/linux_crypto/api.h
# using GNU Radio's standard __GR_ATTR_EXPORT/__GR_ATTR_IMPORT macros

########################################################################
# Library sources
########################################################################
set(gr_linux_crypto_sources
    lib/kernel_keyring_source_impl.cc
    lib/nitrokey_interface_impl.cc
    lib/kernel_crypto_aes_impl.cc
    lib/openpgp_card_helper.cc
)

if(OPENSSL_FOUND)
    list(APPEND gr_linux_crypto_sources
        lib/brainpool_ec_impl.cc
        lib/brainpool_ecies_encrypt_impl.cc
        lib/brainpool_ecies_decrypt_impl.cc
        lib/brainpool_ecies_multi_encrypt_impl.cc
        lib/brainpool_ecies_multi_decrypt_impl.cc
        lib/brainpool_ecdsa_sign_impl.cc
        lib/brainpool_ecdsa_verify_impl.cc
    )
endif()

set(gr_linux_crypto_headers
    lib/kernel_keyring_source_impl.h
    lib/openpgp_card_helper.h
    lib/nitrokey_interface_impl.h
    lib/kernel_crypto_aes_impl.h
)

if(OPENSSL_FOUND)
    list(APPEND gr_linux_crypto_headers
        lib/brainpool_ec_impl.h
        lib/brainpool_ecies_encrypt_impl.h
        lib/brainpool_ecies_decrypt_impl.h
        lib/brainpool_ecies_multi_encrypt_impl.h
        lib/brainpool_ecies_multi_decrypt_impl.h
        lib/brainpool_ecdsa_sign_impl.h
        lib/brainpool_ecdsa_verify_impl.h
    )
endif()

########################################################################
# Create library
########################################################################
add_library(gnuradio-linux-crypto SHARED ${gr_linux_crypto_sources})

# Ensure GNU Radio libraries are linked
# gr_register_component should set GNURADIO_LIBRARIES, but if not, use pkg-config
if(NOT GNURADIO_LIBRARIES)
    pkg_check_modules(GNURADIO_PMT gnuradio-pmt)
    set(GNURADIO_LIBRARIES ${GNURADIO_RUNTIME_LIBRARIES})
    if(GNURADIO_PMT_FOUND)
        list(APPEND GNURADIO_LIBRARIES ${GNURADIO_PMT_LIBRARIES})
    endif()
endif()

# If still empty, use direct library names
if(NOT GNURADIO_LIBRARIES)
    set(GNURADIO_LIBRARIES gnuradio-runtime)
    pkg_check_modules(GNURADIO_PMT QUIET gnuradio-pmt)
    if(GNURADIO_PMT_FOUND)
        list(APPEND GNURADIO_LIBRARIES gnuradio-pmt)
    endif()
endif()

target_link_libraries(gnuradio-linux-crypto
    ${GNURADIO_LIBRARIES}
    ${KEYUTILS_LIBRARIES}
)

# Add optional dependencies
if(OPENSSL_FOUND)
    target_link_libraries(gnuradio-linux-crypto ${OPENSSL_LIBRARIES})
    target_compile_definitions(gnuradio-linux-crypto PRIVATE HAVE_OPENSSL)
endif()

if(SODIUM_FOUND)
    target_link_libraries(gnuradio-linux-crypto ${SODIUM_LIBRARIES})
    target_compile_definitions(gnuradio-linux-crypto PRIVATE HAVE_SODIUM)
endif()

if(GPGME_FOUND)
    target_link_libraries(gnuradio-linux-crypto ${GPGME_LIBRARIES})
    target_include_directories(gnuradio-linux-crypto PRIVATE ${GPGME_INCLUDE_DIRS})
    target_compile_definitions(gnuradio-linux-crypto PRIVATE HAVE_GPGME)
endif()

if(NITROKEY_FOUND)
    target_link_libraries(gnuradio-linux-crypto ${NITROKEY_LIBRARIES})
    target_include_directories(gnuradio-linux-crypto PRIVATE ${NITROKEY_INCLUDE_DIRS})
    target_compile_definitions(gnuradio-linux-crypto PRIVATE HAVE_NITROKEY)
endif()

# Set library properties
set_target_properties(gnuradio-linux-crypto PROPERTIES
    VERSION ${GNURADIO_VERSION}
    SOVERSION ${GNURADIO_SOVERSION}
)

########################################################################
# Python bindings
########################################################################
if(ENABLE_PYTHON)
    find_package(Python3 COMPONENTS Interpreter Development)
    find_package(pybind11 REQUIRED)
    
    # Create Python bindings
    pybind11_add_module(linux_crypto_python
        python/linux_crypto_python.cc
        python/linux_crypto_integration.py
    )
    
    target_link_libraries(linux_crypto_python PRIVATE
        gnuradio-linux-crypto
        gnuradio-runtime
        gnuradio-pmt
    )
    
    # Add OpenSSL support to Python bindings if available
    if(OPENSSL_FOUND)
        target_link_libraries(linux_crypto_python PRIVATE ${OPENSSL_LIBRARIES})
        target_compile_definitions(linux_crypto_python PRIVATE HAVE_OPENSSL)
    endif()
    
    # Set RPATH so Python module can find the library
    set_target_properties(linux_crypto_python PROPERTIES
        INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib"
        BUILD_WITH_INSTALL_RPATH TRUE
    )
    
    # Install Python module
    install(TARGETS linux_crypto_python
        DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/python3/dist-packages
    )
    
    # Install Python wrapper module to gnuradio package
    install(FILES python/gnuradio_linux_crypto_init.py
        DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/python3/dist-packages/gnuradio
        RENAME linux_crypto.py
    )
endif()

########################################################################
# GRC blocks
########################################################################
if(ENABLE_GRC)
    install(DIRECTORY grc/
        DESTINATION ${CMAKE_INSTALL_PREFIX}/share/gnuradio/grc/blocks
        FILES_MATCHING PATTERN "*.yml"
    )
endif()

########################################################################
# Examples
########################################################################
if(ENABLE_EXAMPLES)
    install(DIRECTORY examples/
        DESTINATION ${CMAKE_INSTALL_PREFIX}/share/gr-linux-crypto/examples
        FILES_MATCHING PATTERN "*.py"
    )
endif()

########################################################################
# Documentation
########################################################################
if(ENABLE_DOXYGEN)
    find_package(Doxygen)
    if(DOXYGEN_FOUND)
        install(DIRECTORY docs/
            DESTINATION ${CMAKE_INSTALL_PREFIX}/share/gr-linux-crypto/docs
        )
    endif()
endif()

########################################################################
# Installation
########################################################################
install(TARGETS gnuradio-linux-crypto
    EXPORT gnuradio-linux-crypto-targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/lib
    ARCHIVE DESTINATION ${CMAKE_INSTALL_PREFIX}/lib
    RUNTIME DESTINATION ${CMAKE_INSTALL_PREFIX}/bin
)

install(DIRECTORY include/gnuradio/linux_crypto/
    DESTINATION ${CMAKE_INSTALL_PREFIX}/include/gnuradio/linux_crypto
    FILES_MATCHING PATTERN "*.h"
)

########################################################################
# Testing
########################################################################
if(ENABLE_TESTING)
    enable_testing()
    
    # Test targets will be added when test files are created
    message(STATUS "  Testing enabled but no test files found")
endif()

########################################################################
# Fuzzing (optional)
########################################################################
if(ENABLE_FUZZING)
    find_program(AFL_PLUS_PLUS afl-fuzz)
    if(AFL_PLUS_PLUS)
        # Add fuzzing targets
        add_executable(fuzz_kernel_keyring
            security/fuzzing/kernel_keyring_fuzz_adapted.cpp
        )
        target_link_libraries(fuzz_kernel_keyring
            gnuradio-linux-crypto
            ${GNURADIO_LIBRARIES}
        )
        
        # Install fuzzing scripts
        install(DIRECTORY security/fuzzing/
            DESTINATION ${CMAKE_INSTALL_PREFIX}/share/gr-linux-crypto/fuzzing
            FILES_MATCHING PATTERN "*.cpp" PATTERN "*.sh"
        )
    endif()
endif()

########################################################################
# Uninstall target
########################################################################
# Configure uninstall script
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake_uninstall.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
    IMMEDIATE @ONLY
)

# Add uninstall target
add_custom_target(uninstall
    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake
    COMMENT "Uninstalling gr-linux-crypto"
)

########################################################################
# Configuration summary
########################################################################
message(STATUS "gr-linux-crypto configuration:")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
if(DEFINED GNURADIO_RUNTIME_VERSION)
    message(STATUS "  GNU Radio version: ${GNURADIO_RUNTIME_VERSION} (minimum: ${GNURADIO_MIN_VERSION})")
else()
    message(STATUS "  GNU Radio version: ${GNURADIO_VERSION} (version check unavailable)")
endif()
message(STATUS "  OpenSSL support: ${OPENSSL_FOUND}")
message(STATUS "  Sodium support: ${SODIUM_FOUND}")
message(STATUS "  GPGME support: ${GPGME_FOUND}")
message(STATUS "  Nitrokey support: ${NITROKEY_FOUND}")
message(STATUS "  Python bindings: ${ENABLE_PYTHON}")
message(STATUS "  GRC blocks: ${ENABLE_GRC}")
message(STATUS "  Examples: ${ENABLE_EXAMPLES}")
message(STATUS "  Documentation: ${ENABLE_DOXYGEN}")
message(STATUS "  Testing: ${ENABLE_TESTING}")
message(STATUS "  Fuzzing: ${ENABLE_FUZZING}")
message(STATUS "")
message(STATUS "  Forward compatibility: Designed for future GNU Radio versions")
message(STATUS "  See COMPATIBILITY.md for version compatibility details")

endif(ENABLE_GR_LINUX_CRYPTO)