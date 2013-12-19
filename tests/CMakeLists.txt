project(tests C)

include_directories(
  ${CMAKE_BINARY_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMOCKA_INCLUDE_DIR}
)

if (OSX)
    set(TEST_ENVIRONMENT DYLD_FORCE_FLAT_NAMESPACE=1;DYLD_INSERT_LIBRARIES=${CMAKE_BINARY_DIR}/src/libuid_wrapper.dylib;UID_WRAPPER=1)
else ()
    set(TEST_ENVIRONMENT LD_PRELOAD=${CMAKE_BINARY_DIR}/src/libuid_wrapper.so;UID_WRAPPER=1)
endif ()

add_cmocka_test(testsuite testsuite.c ${CMOCKA_LIBRARY})
set_property(
    TEST
        testsuite
    PROPERTY
        ENVIRONMENT ${TEST_ENVIRONMENT})

if (LINUX)
add_cmocka_test(test_glibc_thread_support test_glibc_thread_support.c ${CMOCKA_LIBRARY})
target_link_libraries(test_glibc_thread_support ${CMAKE_THREAD_LIBS_INIT})
set_property(
    TEST
        test_glibc_thread_support
    PROPERTY
        ENVIRONMENT ${TEST_ENVIRONMENT})
endif(LINUX)

if (LINUX)
    add_executable(getuids getuids.c)
endif (LINUX)

add_cmocka_test(test_uwrap_disabled test_uwrap_disabled.c ${CMOCKA_LIBRARY})
set_property(
    TEST
        test_uwrap_disabled
    PROPERTY
        ENVIRONMENT LD_PRELOAD=${CMAKE_BINARY_DIR}/src/libuid_wrapper.so)
