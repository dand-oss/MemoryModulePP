cmake_minimum_required(VERSION 3.30)
project(MemoryModulePP
    LANGUAGES CXX
    VERSION 1.1.0
    DESCRIPTION "DLL Memory Loader"
    HOMEPAGE_URL "https://github.com/dand-oss/memorymodulepp")

# Define static library target
set(static_libname "MemoryModulePP-static")
add_library(${static_libname} STATIC)

# Define shared library target
set(shared_libname "MemoryModulePP-shared")
add_library(${shared_libname} SHARED)

# turn on "reflection"
target_compile_definitions(${shared_libname} PRIVATE _USRDLL)

# link libraries for DLL
target_link_libraries(${shared_libname} PRIVATE lib_detours)

# Common sources and headers for both libraries
set(common_sources
    BaseAddressIndex.cpp
    ImportTable.cpp
    Initialize.cpp
    InvertedFunctionTable.cpp
    LdrEntry.cpp
    LoadDllMemoryApi.cpp
    Loader.cpp
    MemoryModule.cpp
    MmpDotNet.cpp
    MmpLdrpTls.cpp
    MmpTls.cpp
    MmpTlsFiber.cpp
    ReflectiveLoader.c
    Utils.cpp

    # exports
    MemoryModulePP.def
)

set(common_public_headers
    BaseAddressIndex.h
    ImportTable.h
    Initialize.h
    InvertedFunctionTable.h
    LdrEntry.h
    LoadDllMemoryApi.h
    Loader.h
    MemoryModule.h
    MmpGlobalData.h
    MmpDotNet.h
    MmpTls.h
    Utils.h
)

set(common_private_headers
    LoaderPrivate.h
    MmpTlsFiber.h
    MmpTlsp.h
    ReflectiveDLLInjection.h
    ReflectiveLoader.h
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

  # key definitions
  target_compile_definitions(${libname} PRIVATE
    _HAS_AUTO_INITIALIZE
  )
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
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

# Use configure_package_config_file to properly expand @PACKAGE_INIT@
configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/../${PROJECT_NAME}Config.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
    INSTALL_DESTINATION lib/cmake/${PROJECT_NAME}
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake"
    DESTINATION lib/cmake/${PROJECT_NAME}
)

# CPack configuration for packaging
set(CPACK_PACKAGE_NAME "${PROJECT_NAME}")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_DESCRIPTION "DLL Memory Loader")
set(CPACK_PACKAGE_VENDOR "xAI")
set(CPACK_GENERATOR "ZIP;TGZ")
include(CPack)