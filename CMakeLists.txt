cmake_minimum_required(VERSION 3.20 FATAL_ERROR)
project(
  vigenere-provider
  VERSION 1.2
  DESCRIPTION "A very small demonstration that shows the minimum required things for a cipher in an OpenSSL 3.0 module, including provider specific error reasons."
  LANGUAGES C)
set(CMAKE_C_STANDARD 99)
# I use my github handle here
add_compile_definitions(AUTHOR="@levitte")

enable_testing()

add_subdirectory(libprov)
include(libprov/cmake/provider.cmake)
setup_provider_openssl()

add_custom_command(OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/v_params.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/v_params.h
                   COMMAND perl ${CMAKE_CURRENT_SOURCE_DIR}/libprov/perl/gen_param_LL.pl
                           ${CMAKE_CURRENT_SOURCE_DIR}/v_params.c
                           ${CMAKE_CURRENT_SOURCE_DIR}/v_params.h
                           ${CMAKE_CURRENT_SOURCE_DIR}/vigenere_params.dat
                   MAIN_DEPENDENCY vigenere_params.dat
                   DEPENDS libprov/perl/gen_param_LL.pl)

set(vigenere_source vigenere.c v_params.c)
build_provider(vigenere "${vigenere_source}" libprov)

# Testing
get_property(_is_multiconfig GLOBAL PROPERTY GENERATOR_IS_MULTI_CONFIG)
if (_is_multiconfig)
  set(VIGENERE_MODULE_DIRECTORY "${CMAKE_BINARY_DIR}/$<CONFIG>")
else()
  set(VIGENERE_MODULE_DIRECTORY "${CMAKE_BINARY_DIR}")
endif()
unset(_is_multiconfig)
message(STATUS "Determined the build time Vigenere provider location to be '${VIGENERE_MODULE_DIRECTORY}'")

set(TEST_ENVIRONMENT
  "OPENSSL_MODULES=${VIGENERE_MODULE_DIRECTORY}"
  "OPENSSL_PROGRAM=${OPENSSL_PROGRAM}"
  "OPENSSL_RUNTIME_DIR=${OPENSSL_RUNTIME_DIR}"
  "OPENSSL_LIBRARY_DIR=$<IF:$<BOOL:${WIN32}>,${OPENSSL_RUNTIME_DIR},${OPENSSL_LIBRARY_DIR}>"
  "SOURCEDIR=${CMAKE_CURRENT_SOURCE_DIR}"
  "PERL5LIB=${CMAKE_CURRENT_SOURCE_DIR}/t"
  )

add_library(test_common STATIC test_common.c)
target_include_directories(test_common PUBLIC ${OPENSSL_INCLUDE_DIR})

add_executable(test_vigenere test_vigenere.c)
target_link_libraries(test_vigenere
  PRIVATE test_common OpenSSL::Crypto)
add_test(NAME vigenere COMMAND test_vigenere)
set_tests_properties(vigenere PROPERTIES ENVIRONMENT "${TEST_ENVIRONMENT}")

add_executable(test_vigenere_err
  test_vigenere_err.c)
if (MSVC)
  target_link_libraries(test_vigenere_err
    PRIVATE test_common OpenSSL::Crypto OpenSSL::applink)
else ()
  target_link_libraries(test_vigenere_err
    PRIVATE test_common OpenSSL::Crypto)
endif ()
add_test(NAME vigenere_err COMMAND test_vigenere_err)
set_tests_properties(vigenere_err PROPERTIES ENVIRONMENT "${TEST_ENVIRONMENT}")

if (WIN32)
  if (DEFINED OPENSSL_LIBCRYPTO_SHARED)
    cmake_path(GET OPENSSL_LIBCRYPTO_SHARED STEM OPENSSL_LIBCRYPTO_SHARED_NAME)
    add_custom_command(
      TARGET test_vigenere POST_BUILD
      COMMAND cmake -E copy
        "${OPENSSL_LIBCRYPTO_SHARED}"
        "${VIGENERE_MODULE_DIRECTORY}/${OPENSSL_LIBCRYPTO_SHARED_NAME}.dll")
    add_custom_command(
      TARGET test_vigenere_err POST_BUILD
      COMMAND cmake -E copy
        "${OPENSSL_LIBCRYPTO_SHARED}"
        "${VIGENERE_MODULE_DIRECTORY}/${OPENSSL_LIBCRYPTO_SHARED_NAME}.dll")
  endif()
endif()

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
