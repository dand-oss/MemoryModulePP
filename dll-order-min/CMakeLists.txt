cmake_minimum_required(VERSION 3.30)
project(dll-order-min LANGUAGES CXX)

# Define static library target
set(static_libname "dll-order-min-static")
add_library(${static_libname} STATIC)

# Define shared library target
set(shared_libname "dll-order-min-shared")
add_library(${shared_libname} SHARED)

# link libraries for DLL
target_link_libraries(${shared_libname} PRIVATE ntdll)
# Export
set_target_properties(${shared_libname} PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)

# Common sources and headers for both libraries
set(common_sources
    dll-order-min.cpp
)

set(common_public_headers
    dll-order-min.h
)

set(common_private_headers
)

# Specify sources and headers for static library
target_sources(${static_libname}
  PRIVATE
    ${common_sources}
  PUBLIC
    FILE_SET HEADERS
    BASE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}
    FILES
      ${common_public_headers}
  PRIVATE
    FILE_SET private_headers
    TYPE HEADERS
    BASE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}
    FILES
      ${common_private_headers}
)

# Specify sources and headers for shared library
target_sources(${shared_libname}
  PRIVATE
    ${common_sources}
  PUBLIC
    FILE_SET HEADERS
    BASE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}
    FILES
      ${common_public_headers}
  PRIVATE
    FILE_SET private_headers
    TYPE HEADERS
    BASE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}
    FILES
      ${common_private_headers}
)

# Set include directories for libraries
foreach(libname ${static_libname} ${shared_libname})
  target_include_directories(${libname}
    PUBLIC
      $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
      $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>
      $<INSTALL_INTERFACE:include>
  )

  # Ensure C++ standard
  target_compile_features(${libname} PRIVATE cxx_std_23)

endforeach()

# Install libraries and public headers
install(TARGETS ${static_libname} ${shared_libname}
    EXPORT ${PROJECT_NAME}Targets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
    FILE_SET HEADERS DESTINATION include
)

# Install export file
install(EXPORT ${PROJECT_NAME}Targets
    FILE ${PROJECT_NAME}Targets.cmake
    NAMESPACE ${PROJECT_NAME}::
    DESTINATION lib/cmake/${PROJECT_NAME}
)

# Generate and install CMake config file
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake"
    VERSION 1.0.0
    COMPATIBILITY SameMajorVersion
)

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/${PROJECT_NAME}Config.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
    @ONLY
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake"
    DESTINATION lib/cmake/${PROJECT_NAME}
)

# CPack configuration for packaging
set(CPACK_PACKAGE_NAME "${PROJECT_NAME}")
set(CPACK_PACKAGE_VERSION "1.0.0")
set(CPACK_PACKAGE_DESCRIPTION "A custom Dll Order implementation")
set(CPACK_PACKAGE_VENDOR "xAI")
set(CPACK_GENERATOR "ZIP;TGZ")
include(CPack)
