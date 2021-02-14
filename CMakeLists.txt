cmake_minimum_required(VERSION 3.0 FATAL_ERROR)
project(
  vigenere-provider
  VERSION 1.0
  DESCRIPTION "A very small demonstration that shows the minimum required things for a cipher in an OpenSSL 3.0 module, including provider specific error reasons."
  LANGUAGES C)
set(CMAKE_C_STANDARD 99)

include(CheckLibraryExists)
include(CheckFunctionExists)

enable_testing()

find_package(OpenSSL 3.0 REQUIRED)

find_program(OPENSSL_PROGRAM openssl
  PATHS ${OPENSSL_ROOT_DIR} PATH_SUFFIXES apps bin NO_DEFAULT_PATH)
message("-- Found OpenSSL application: ${OPENSSL_PROGRAM}")

if (DEFINED MSVC_VERSION)
  # FindOpenSSL.cmake assumes http://www.slproweb.com/products/Win32OpenSSL.html
  # and gets it quite wrong when an install from OpenSSL source is present
  if (NOT EXISTS ${OPENSSL_CRYPTO_LIBRARY})
    set(OPENSSL_CRYPTO_LIBRARY ${OPENSSL_ROOT_DIR}/lib/libcrypto.lib)
  endif()
  if (NOT EXISTS ${OPENSSL_SSL_LIBRARY})
    set(OPENSSL_SSL_LIBRARY ${OPENSSL_ROOT_DIR}/lib/libssl.lib)
  endif()
endif()

add_subdirectory(libprov)

# Provider module
add_library(vigenere MODULE vigenere.c)
set_target_properties(vigenere PROPERTIES PREFIX "" OUTPUT_NAME "vigenere")
target_include_directories(vigenere PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(vigenere PRIVATE libprov ${OPENSSL_CRYPTO_LIBRARY})

# Testing
set(TEST_ENVIRONMENT
  OPENSSL_MODULES=${CMAKE_BINARY_DIR}
  OPENSSL_PROGRAM=${OPENSSL_PROGRAM}
  OPENSSL_CRYPTO_LIBRARY=${OPENSSL_CRYPTO_LIBRARY}
  SOURCEDIR=${CMAKE_CURRENT_SOURCE_DIR}
  PERL5LIB=${CMAKE_CURRENT_SOURCE_DIR}/t
  )

add_library(test_common STATIC test_common.c)
add_executable(test_vigenere test_vigenere.c)
target_include_directories(test_vigenere PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(test_vigenere
  PRIVATE test_common ${OPENSSL_CRYPTO_LIBRARY})
add_test(NAME vigenere COMMAND test_vigenere)
set_tests_properties(vigenere PROPERTIES ENVIRONMENT "${TEST_ENVIRONMENT}")

add_executable(test_vigenere_err test_vigenere_err.c)
target_include_directories(test_vigenere_err PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(test_vigenere_err
  PRIVATE test_common ${OPENSSL_CRYPTO_LIBRARY})
add_test(NAME vigenere_err COMMAND test_vigenere_err)
set_tests_properties(vigenere_err PROPERTIES ENVIRONMENT "${TEST_ENVIRONMENT}")

# Test with OpenSSL, using TAP
add_test(NAME openssl
  COMMAND prove -PWrapOpenSSL ${CMAKE_CURRENT_SOURCE_DIR}/t)
set_tests_properties(openssl PROPERTIES ENVIRONMENT "${TEST_ENVIRONMENT}")

# No installation instruction, as this should never be used in production
# If you still want to do so, just copy vigenere.so / vigenere.dll to an
# appropriate location.
