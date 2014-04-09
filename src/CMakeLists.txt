project(libuid_wrapper C)

include_directories(${CMAKE_BINARY_DIR})
add_library(uid_wrapper SHARED uid_wrapper.c)
target_link_libraries(uid_wrapper ${UIDWRAP_REQUIRED_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})

set_target_properties(
  uid_wrapper
    PROPERTIES
      VERSION
        ${LIBRARY_VERSION}
      SOVERSION
        ${LIBRARY_SOVERSION}
)

install(
  TARGETS
    uid_wrapper
  RUNTIME DESTINATION ${BIN_INSTALL_DIR}
  LIBRARY DESTINATION ${LIB_INSTALL_DIR}
  ARCHIVE DESTINATION ${LIB_INSTALL_DIR}
)

# This needs to be at the end
if (CMAKE_VERSION VERSION_GREATER 2.8.13)
    cmake_policy(SET CMP0026 OLD)
endif()
get_target_property(UWRAP_LOCATION uid_wrapper LOCATION)
set(UID_WRAPPER_LOCATION ${UWRAP_LOCATION} PARENT_SCOPE)
