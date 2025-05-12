cmake_minimum_required(VERSION 3.27)
project(mmtest LANGUAGES CXX)

# Define executable targets
set(static_exename "mmtest-static")
add_executable(${static_exename})

set(shared_exename "mmtest-shared")
add_executable(${shared_exename})

set(reflect_exename "mmtest-reflect")
add_executable(${reflect_exename})

# static requires more libs
target_link_libraries(${static_exename} PRIVATE lib_detours)

# use install directory under build to assemble tests
set( INSTALL_DIR "${CMAKE_BINARY_DIR}/install")

foreach(exename ${static_exename} ${shared_exename} ${reflect_exename} )

    # common sources and libs
    target_sources(${exename} PRIVATE test.cpp)
    target_link_libraries(${exename} PRIVATE MemoryModulePP-shared)

    # copy exes into install dir
    install(TARGETS ${exename} RUNTIME DESTINATION ${INSTALL_DIR})

    # set a_d.dll path as command arg in VS debugger
    file(TO_NATIVE_PATH "$<TARGET_FILE:a>" A_DLL)
    set_target_properties(${exename} PROPERTIES
        "VS_DEBUGGER_COMMAND_ARGUMENTS"
        "${A_DLL}"
    )
endforeach()
