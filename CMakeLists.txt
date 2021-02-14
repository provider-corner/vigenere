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

if (DEFINED MSVC_VERSION)
  # FindOpenSSL.cmake assumes http://www.slproweb.com/products/Win32OpenSSL.html
  # and gets it quote wrong when an install from OpenSSL source is present
  set(OPENSSL_CRYPTO_LIBRARY ${OPENSSL_ROOT_DIR}/lib/libcrypto.lib)
  set(OPENSSL_SSL_LIBRARY ${OPENSSL_ROOT_DIR}/lib/libssl.lib)
endif()

add_subdirectory(libprov)

# Provider module
add_library(vigenere MODULE vigenere.c)
set_target_properties(vigenere PROPERTIES PREFIX "" OUTPUT_NAME "vigenere")
target_include_directories(vigenere PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(vigenere PRIVATE libprov ${OPENSSL_CRYPTO_LIBRARY})

# Testing
add_library(test_common STATIC test_common.c)
add_executable(test_vigenere test_vigenere.c)
target_include_directories(test_vigenere PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(test_vigenere
  PRIVATE test_common ${OPENSSL_CRYPTO_LIBRARY})
add_test(NAME vigenere COMMAND test_vigenere)
set_tests_properties(vigenere
  PROPERTIES ENVIRONMENT "OPENSSL_MODULES=${CMAKE_BINARY_DIR}"
  )

add_executable(test_vigenere_err test_vigenere_err.c)
target_include_directories(test_vigenere_err PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(test_vigenere_err
  PRIVATE test_common ${OPENSSL_CRYPTO_LIBRARY})
add_test(NAME vigenere_err COMMAND test_vigenere_err)
set_tests_properties(vigenere_err
  PROPERTIES ENVIRONMENT "OPENSSL_MODULES=${CMAKE_BINARY_DIR}"
  )

# No installation instruction, as this should never be used in production
# If you still want to do so, just copy vigenere.so / vigenere.dll to an
# appropriate location.
