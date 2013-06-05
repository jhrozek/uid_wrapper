include(CheckIncludeFile)
include(CheckSymbolExists)
include(CheckFunctionExists)
include(CheckLibraryExists)
include(CheckTypeSize)
include(CheckStructHasMember)
include(CheckPrototypeDefinition)
include(TestBigEndian)

set(PACKAGE ${APPLICATION_NAME})
set(VERSION ${APPLICATION_VERSION})
set(DATADIR ${DATA_INSTALL_DIR})
set(LIBDIR ${LIB_INSTALL_DIR})
set(PLUGINDIR "${PLUGIN_INSTALL_DIR}-${LIBRARY_SOVERSION}")
set(SYSCONFDIR ${SYSCONF_INSTALL_DIR})

set(BINARYDIR ${CMAKE_BINARY_DIR})
set(SOURCEDIR ${CMAKE_SOURCE_DIR})

function(COMPILER_DUMPVERSION _OUTPUT_VERSION)
    # Remove whitespaces from the argument.
    # This is needed for CC="ccache gcc" cmake ..
    string(REPLACE " " "" _C_COMPILER_ARG "${CMAKE_C_COMPILER_ARG1}")

    execute_process(
        COMMAND
            ${CMAKE_C_COMPILER} ${_C_COMPILER_ARG} -dumpversion
        OUTPUT_VARIABLE _COMPILER_VERSION
    )

    string(REGEX REPLACE "([0-9])\\.([0-9])(\\.[0-9])?" "\\1\\2"
           _COMPILER_VERSION "${_COMPILER_VERSION}")

    set(${_OUTPUT_VERSION} ${_COMPILER_VERSION} PARENT_SCOPE)
endfunction()

if(CMAKE_COMPILER_IS_GNUCC AND NOT MINGW AND NOT OS2)
    compiler_dumpversion(GNUCC_VERSION)
    if (NOT GNUCC_VERSION EQUAL 34)
        set(CMAKE_REQUIRED_FLAGS "-fvisibility=hidden")
        check_c_source_compiles(
"void __attribute__((visibility(\"default\"))) test() {}
int main(void){ return 0; }
" WITH_VISIBILITY_HIDDEN)
        set(CMAKE_REQUIRED_FLAGS "")
    endif (NOT GNUCC_VERSION EQUAL 34)
endif(CMAKE_COMPILER_IS_GNUCC AND NOT MINGW AND NOT OS2)

# HEADERS
check_include_file(sys/types.h HAVE_SYS_TYPES_H)
check_include_file(sys/syscall.h HAVE_SYS_SYSCALL_H)
check_include_file(syscall.h HAVE_SYSCALL_H)
check_include_file(grp.h HAVE_GRP_H)
check_include_file(unistd.h HAVE_UNISTD_H)

# FUNCTIONS
check_function_exists(strncpy HAVE_STRNCPY)
check_function_exists(vsnprintf HAVE_VSNPRINTF)
check_function_exists(snprintf HAVE_SNPRINTF)

check_function_exists(seteuid HAVE_SETEUID)
check_function_exists(setreuid HAVE_SETREUID)
check_function_exists(setreuid HAVE_SETRESUID)

check_function_exists(setegid HAVE_SETEGID)
check_function_exists(setregid HAVE_SETREGID)
check_function_exists(setregid HAVE_SETRESGID)

check_function_exists(getgroups HAVE_GETGROUPS)
check_function_exists(setgroups HAVE_SETGROUPS)

check_function_exists(syscall HAVE_SYSCALL)

if (HAVE_SYSCALL)
    add_definitions(-D_GNU_SOURCE)
endif (HAVE_SYSCALL)

check_library_exists(dl dlopen "" HAVE_LIBDL)
if (HAVE_LIBDL)
    find_library(DLFCN_LIBRARY dl)
    set(CMAKE_REQUIRED_LIBRARIES ${CMAKE_REQUIRED_LIBRARIES} ${DLFCN_LIBRARY})
endif (HAVE_LIBDL)

# ENDIAN
if (NOT WIN32)
    test_big_endian(WORDS_BIGENDIAN)
endif (NOT WIN32)

set(UIDWRAP_REQUIRED_LIBRARIES ${CMAKE_REQUIRED_LIBRARIES} CACHE INTERNAL "uidwrap required system libraries")
