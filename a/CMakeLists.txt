cmake_minimum_required(VERSION 3.30)
project(a-sample LANGUAGES CXX)

set(libname "a")

add_library(${libname} SHARED)
target_link_libraries(${libname} PRIVATE lib_detours)
target_sources(${libname} PRIVATE
    # sources
    dllmain.cpp
    exception.cpp
    gdiplus.cpp
    thread.cpp

    # exports
    m.def

    # resources
    a.rc
    resource.h
)

# put dll in local install dir
set( INSTALL_DIR "${CMAKE_BINARY_DIR}/install")
install(TARGETS ${libname}
    LIBRARY DESTINATION ${INSTALL_DIR}
    ARCHIVE DESTINATION ${INSTALL_DIR}
    RUNTIME DESTINATION ${INSTALL_DIR}
)
