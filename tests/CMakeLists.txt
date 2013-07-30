project(tests C)

include_directories(
  ${CMAKE_BINARY_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMOCKA_INCLUDE_DIR}
)

set(TEST_ENVIRONMENT LD_PRELOAD=${CMAKE_BINARY_DIR}/src/libuid_wrapper.so;UID_WRAPPER=1)

add_cmocka_test(testsuite testsuite.c ${CMOCKA_LIBRARY})
set_property(
    TEST
        testsuite
    PROPERTY
        ENVIRONMENT ${TEST_ENVIRONMENT})

add_executable(getuids getuids.c)
