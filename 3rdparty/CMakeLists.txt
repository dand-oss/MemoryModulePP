cmake_minimum_required(VERSION 3.30)
project(Detours
    LANGUAGES CXX
    VERSION 1.0.0
    DESCRIPTION "Microsoft Detours Library")

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(libname lib_detours)
set(DETOURS_SOURCE Detours)

add_library(${libname} STATIC)

# Public headers that should be installed
set(public_headers
    ${DETOURS_SOURCE}/detours.h
    ${DETOURS_SOURCE}/detver.h
)

# Set public headers using file sets
target_sources(${libname}
    PUBLIC
        FILE_SET HEADERS
        BASE_DIRS ${DETOURS_SOURCE}
        FILES ${public_headers}
    PRIVATE
        ${DETOURS_SOURCE}/creatwth.cpp
        ${DETOURS_SOURCE}/detours.cpp
        ${DETOURS_SOURCE}/disasm.cpp
        ${DETOURS_SOURCE}/disolarm.cpp
        ${DETOURS_SOURCE}/disolarm64.cpp
        ${DETOURS_SOURCE}/disolia64.cpp
        ${DETOURS_SOURCE}/disolx64.cpp
        ${DETOURS_SOURCE}/disolx86.cpp
        ${DETOURS_SOURCE}/image.cpp
        ${DETOURS_SOURCE}/modules.cpp
        ${DETOURS_SOURCE}/uimports.cpp
)

target_include_directories(${libname}
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/${DETOURS_SOURCE}>
        $<INSTALL_INTERFACE:include>
)

# This file is included and not compiled on its own
set_property (
    SOURCE ${DETOURS_SOURCE}/uimports.cpp
    APPEND PROPERTY HEADER_FILE_ONLY true)

# Install libraries and public headers
install(TARGETS ${libname}
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
    "${CMAKE_CURRENT_SOURCE_DIR}/${PROJECT_NAME}Config.cmake.in"
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
set(CPACK_PACKAGE_DESCRIPTION "Microsoft Detours Library")
set(CPACK_PACKAGE_VENDOR "xAI")
set(CPACK_GENERATOR "ZIP;TGZ")
include(CPack)
