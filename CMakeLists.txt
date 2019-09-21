cmake_minimum_required(VERSION 3.0 FATAL_ERROR)
project(vigenere-provider LANGUAGES C)
set(CMAKE_C_STANDARD 90)

include(CheckLibraryExists)
include(CheckFunctionExists)

enable_testing()

find_package(OpenSSL 3.0 REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

# Main provider
add_library(vigenere MODULE vigenere.c)
set_target_properties(vigenere PROPERTIES PREFIX "" OUTPUT_NAME "vigenere")

# Testing
add_executable(test_vigenere test_vigenere.c)
target_link_libraries(test_vigenere ${OPENSSL_CRYPTO_LIBRARY})
add_test(NAME vigenere COMMAND test_vigenere)
set_tests_properties(vigenere
  PROPERTIES ENVIRONMENT "OPENSSL_MODULES=${CMAKE_BINARY_DIR}"
  )

# No installation instruction, as this should never be used in production
# If you still want to do so, just copy vigenere.so / vigenere.dll to an
# appropriate location.
