project(libuid_wrapper C)

include_directories(${CMAKE_BINARY_DIR})
add_library(uid_wrapper SHARED uid_wrapper.c)
target_link_libraries(uid_wrapper ${UIDWRAP_REQUIRED_LIBRARIES})

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
