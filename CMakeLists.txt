cmake_minimum_required(VERSION 3.12 FATAL_ERROR)
project(
  vigenere-provider
  VERSION 1.1
  DESCRIPTION "A very small demonstration that shows the minimum required things for a cipher in an OpenSSL 3.0 module, including provider specific error reasons."
  LANGUAGES C)
set(CMAKE_C_STANDARD 99)

enable_testing()

add_subdirectory(libprov)
include(libprov/cmake/provider.cmake)
build_provider(vigenere vigenere.c libprov)

# Testing
if (MSVC)
  # This is frustrating!  I've tried guessing at all sorts of variables,
  # as well as getting the target property LIBRARY_OUTPUT_DIRECTORY using
  # get_target_property() as well as generator expressions, but to not avail.
  # So for now, the MODULES path gets hardcoded from observed builds.
  if (NOT CMAKE_BUILD_TYPE)
    # From observation, it seems that Debug is the default
    set(VIGENERE_MODULE_DIRECTORY "${CMAKE_BINARY_DIR}/Debug")
  else()
    set(VIGENERE_MODULE_DIRECTORY "${CMAKE_BINARY_DIR}/${CMAKE_BUILD_TYPE}")
  endif()
else()
  set(VIGENERE_MODULE_DIRECTORY "${CMAKE_BINARY_DIR}")
endif()
message(STATUS "Determined the Vigenere provider location to '${VIGENERE_MODULE_DIRECTORY}'")

set(TEST_ENVIRONMENT
  OPENSSL_MODULES=${VIGENERE_MODULE_DIRECTORY}
  OPENSSL_PROGRAM=${OPENSSL_PROGRAM}
  OPENSSL_CRYPTO_LIBRARY=${OPENSSL_CRYPTO_LIBRARY}
  SOURCEDIR=${CMAKE_CURRENT_SOURCE_DIR}
  PERL5LIB=${CMAKE_CURRENT_SOURCE_DIR}/t
  )

add_library(test_common STATIC test_common.c)
target_include_directories(test_common PUBLIC ${OPENSSL_INCLUDE_DIR})

add_executable(test_vigenere test_vigenere.c)
target_link_libraries(test_vigenere
  PRIVATE test_common ${OPENSSL_CRYPTO_LIBRARIES})
add_test(NAME vigenere COMMAND test_vigenere)
set_tests_properties(vigenere PROPERTIES ENVIRONMENT "${TEST_ENVIRONMENT}")

add_executable(test_vigenere_err
  test_vigenere_err.c ${OPENSSL_APPLINK_SOURCE})
target_link_libraries(test_vigenere_err
  PRIVATE test_common ${OPENSSL_CRYPTO_LIBRARIES})
add_test(NAME vigenere_err COMMAND test_vigenere_err)
set_tests_properties(vigenere_err PROPERTIES ENVIRONMENT "${TEST_ENVIRONMENT}")

# Test with OpenSSL, using TAP
if (MSVC)
  set(PROVE prove.bat)
else()
  set(PROVE prove)
endif()
add_test(NAME openssl
  COMMAND ${PROVE} -PWrapOpenSSL ${CMAKE_CURRENT_SOURCE_DIR}/t)
set_tests_properties(openssl PROPERTIES ENVIRONMENT "${TEST_ENVIRONMENT}")

# No installation instruction, as this should never be used in production
# If you still want to do so, just copy vigenere.so / vigenere.dll to an
# appropriate location.
