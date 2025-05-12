cmake_minimum_required(VERSION 3.30)
project(lib-MemoryModule LANGUAGES CXX)

# Define static library target
set(static_libname "MemoryModulePP-static")
add_library(${static_libname} STATIC)

# Define shared library target
set(shared_libname "MemoryModulePP-shared")
add_library(${shared_libname} SHARED)

# Define reflective shared library target
set(reflect_libname "MemoryModulePP-relfect-shared")
add_library(${reflect_libname} SHARED)

# turn on "reflection"
target_compile_definitions(${reflect_libname} PRIVATE _USRDLL)

# link libraries for DLL
foreach(libname ${shared_libname} ${reflect_libname})
    target_link_libraries(${libname}
      PRIVATE
        lib_detours
    )
endforeach()

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

# Specify sources and headers for reflected library
target_sources(${reflect_libname}
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
foreach(libname ${static_libname} ${shared_libname} ${reflect_libname} )
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
    _MEMORY_MODULE
    _HAS_AUTO_INITIALIZE
  )
endforeach()

# Install libraries and public headers
install(TARGETS ${static_libname} ${shared_libname} ${reflect_libname}
    EXPORT MemoryModulePPTargets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
    FILE_SET HEADERS DESTINATION include
)

# Install export file
install(EXPORT MemoryModulePPTargets
    FILE MemoryModulePPTargets.cmake
    NAMESPACE MemoryModulePP::
    DESTINATION lib/cmake/MemoryModulePP
)

# Generate and install CMake config file
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/MemoryModulePPConfigVersion.cmake"
    VERSION 1.0.0
    COMPATIBILITY SameMajorVersion
)

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/../MemoryModulePPConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/MemoryModulePPConfig.cmake"
    @ONLY
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/MemoryModulePPConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/MemoryModulePPConfigVersion.cmake"
    DESTINATION lib/cmake/MemoryModulePP
)

# CPack configuration for packaging
set(CPACK_PACKAGE_NAME "MemoryModulePP")
set(CPACK_PACKAGE_VERSION "1.0.0")
set(CPACK_PACKAGE_DESCRIPTION "A custom MemoryModulePP implementation")
set(CPACK_PACKAGE_VENDOR "xAI")
set(CPACK_GENERATOR "ZIP;TGZ")
include(CPack)
