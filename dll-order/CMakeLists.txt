cmake_minimum_required(VERSION 3.27)
project(dll-order LANGUAGES CXX)

set(exename "dll-order")
add_executable(${exename})
target_link_libraries(${exename} PRIVATE
    MemoryModulePP-shared
    shlwapi # PathFindOnPathW
    SQLite::SQLite3-shared
    ports::sqlite3pp
)

find_package(SQLite3 CONFIG REQUIRED)
find_port_pkg(sqlite3pp   "sqlite3pp")

# Packages have LIBRARY as interface property
asv_print_package_properties(
    SQLite::SQLite3-shared
    ports::sqlite3pp
    )

# use install directory under build to assemble tests
set( INSTALL_DIR "${CMAKE_BINARY_DIR}/install")

# common sources and libs
target_sources(${exename} PRIVATE dll-order.cpp)

# copy exes into install dir
install(TARGETS ${exename} RUNTIME DESTINATION ${INSTALL_DIR})

# add shared lib to PATH
file(TO_NATIVE_PATH "$<TARGET_FILE_DIR:MemoryModulePP-shared>" MMSHARED_DIR)
set_target_properties(${exename} PROPERTIES
    VS_DEBUGGER_ENVIRONMENT
    "PATH=${MMSHARED_DIR};%PATH%"
)

# pass path to target a_d.dll in VS debugger
set_target_properties(${exename} PROPERTIES
    "VS_DEBUGGER_COMMAND_ARGUMENTS"
    "glueapp_d"
)
