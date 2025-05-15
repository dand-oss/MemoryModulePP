cmake_minimum_required(VERSION 3.27)
project(winhttp-test LANGUAGES CXX)

set(exename "winhttp-test")
add_executable(${exename})
target_link_libraries(${exename} PRIVATE
    MemoryModulePP-shared
    shlwapi # PathFindOnPathW
)

# use install directory under build to assemble tests
set( INSTALL_DIR "${CMAKE_BINARY_DIR}/install")

# common sources and libs
target_sources(${exename} PRIVATE winhttp.cpp)

# copy exes into install dir
install(TARGETS ${exename} RUNTIME DESTINATION ${INSTALL_DIR})
