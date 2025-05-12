cmake_minimum_required(VERSION 3.30)
project(lib-MemoryModule LANGUAGES CXX)

# Define static library target
set(static_libname "MemoryModulePP-static")
add_library(${static_libname} STATIC)

# Define shared library target
set(shared_libname "MemoryModulePP-shared")
add_library(${shared_libname} SHARED)
# export DLL functions
set_target_properties(${shared_libname} PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
# link the dll
target_link_libraries(${shared_libname}
  PRIVATE
    lib_detours
)

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
)

set(common_public_headers
    MemoryModule.h
)

set(common_private_headers
    BaseAddressIndex.h
    ImportTable.h
    Initialize.h
    InvertedFunctionTable.h
    LdrEntry.h
    LoadDllMemoryApi.h
    Loader.h
    LoaderPrivate.h
    MmpDotNet.h
    MmpGlobalData.h
    MmpTls.h
    MmpTlsFiber.h
    MmpTlsp.h
    ReflectiveDLLInjection.h
    ReflectiveLoader.h
    Utils.h
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

# Set include directories for both libraries
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
    _MEMORY_MODULE
    _HAS_AUTO_INITIALIZE
  )
endforeach()

# Install both libraries and public headers
install(TARGETS ${static_libname} ${shared_libname}
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
