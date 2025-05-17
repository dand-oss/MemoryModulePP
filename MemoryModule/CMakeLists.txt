cmake_minimum_required(VERSION 3.30)
project(MemoryModulePP LANGUAGES CXX)

# Define target names
set(static_libname "MemoryModulePP-static")
set(shared_libname "MemoryModulePP-shared")

# Add library targets
add_library(${static_libname} STATIC)
add_library(${shared_libname} SHARED)

# Enable reflection for DLL
target_compile_definitions(${shared_libname} PRIVATE _USRDLL)

# DLL link dependency
target_link_libraries(${shared_libname} PRIVATE lib_detours)

# Common source files
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
    MemoryModulePP.def
)

# Public header files
set(common_public_headers
    stdafx.h
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

# Private headers (not installed)
set(common_private_headers
    LoaderPrivate.h
    MmpTlsFiber.h
    MmpTlsp.h
    ReflectiveDLLInjection.h
    ReflectiveLoader.h
)

# Assign sources and headers to both libraries
foreach(libname ${static_libname} ${shared_libname})
  target_sources(${libname}
    PRIVATE ${common_sources}
    PUBLIC
      FILE_SET HEADERS
      BASE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}
      FILES ${common_public_headers}
    PRIVATE
      FILE_SET private_headers TYPE HEADERS
      BASE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}
      FILES ${common_private_headers}
  )

  target_include_directories(${libname}
    PUBLIC
      $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
      $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>
      $<INSTALL_INTERFACE:include>
  )

  target_compile_features(${libname} PRIVATE cxx_std_23)
  target_compile_definitions(${libname} PRIVATE
    _MEMORY_MODULE
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

# Generate and install package config
include(CMakePackageConfigHelpers)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake"
    VERSION 1.0.0
    COMPATIBILITY SameMajorVersion
)

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/../${PROJECT_NAME}Config.cmake.in"
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
set(CPACK_PACKAGE_DESCRIPTION "A custom MemoryModulePP implementation")
set(CPACK_PACKAGE_VENDOR "xAI")
set(CPACK_GENERATOR "ZIP;TGZ")
include(CPack)
