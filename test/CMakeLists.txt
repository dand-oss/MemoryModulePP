cmake_minimum_required(VERSION 3.27)
project(mmtest LANGUAGES CXX)

# Define executable targets
set(static_exename "mmtest-static")
add_executable(${static_exename})
target_link_libraries(${static_exename} PRIVATE
    MemoryModulePP-static
    lib_detours
)

set(shared_exename "mmtest-shared")
add_executable(${shared_exename})
target_link_libraries(${shared_exename} PRIVATE
    MemoryModulePP-shared
)

# use install directory under build to assemble tests
set( INSTALL_DIR "${CMAKE_BINARY_DIR}/install")

foreach(exename ${static_exename} ${shared_exename})

    # common sources and libs
    target_sources(${exename} PRIVATE test.cpp)

    # copy exes into install dir
    install(TARGETS ${exename} RUNTIME DESTINATION ${INSTALL_DIR})

    # add shared lib to PATH
    file(TO_NATIVE_PATH "$<TARGET_FILE_DIR:MemoryModulePP-shared>" MMSHARED_TARGET)
    string(REGEX REPLACE "/" "\\\\" MMSHARED_PATH ${MMSHARED_TARGET})
    set_target_properties(${exename} PROPERTIES
        VS_DEBUGGER_ENVIRONMENT
        "PATH=${MMSHARED_PATH};%PATH%"
    )

    # pass path to target a_d.dll in VS debugger
    file(TO_NATIVE_PATH "$<TARGET_FILE:a>" A_DLL)
    set_target_properties(${exename} PROPERTIES
        "VS_DEBUGGER_COMMAND_ARGUMENTS"
        "${A_DLL}"
    )
endforeach()
