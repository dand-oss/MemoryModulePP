cmake_minimum_required(VERSION 3.27)
project(db-dll-loader LANGUAGES CXX)

set(exename "db-dll-loader")
add_executable(${exename})
target_include_directories(${exename} PRIVATE
    ${ASI}
    ${ASI}/h
)
target_link_libraries(${exename} PRIVATE
    MemoryModulePP-shared
    SQLite::SQLite3-shared
    ports::sqlite3pp
    cppcrc::cppcrc
    fmt::fmt
    Boost::exception
)

find_package(SQLite3 CONFIG REQUIRED)
find_port_pkg(sqlite3pp   "sqlite3pp")
find_package(cppcrc CONFIG REQUIRED)
list(PREPEND CMAKE_PREFIX_PATH ${ASV_PLAT_PORTS}/fmtlib)
find_package(fmt CONFIG REQUIRED)
find_package(Boost CONFIG REQUIRED COMPONENTS
    exception
    )

# Packages have LIBRARY as interface property
asv_print_package_properties(
    SQLite::SQLite3-shared
    ports::sqlite3pp
    cppcrc::cppcrc
    # Boost::system
    fmt::fmt
    Boost::exception
    )

# use install directory under build to assemble tests
set( INSTALL_DIR "${CMAKE_BINARY_DIR}/install")

# common sources and libs
target_sources(${exename} PRIVATE
    0.cpp #
    api-set.cpp
    db-dll-loader.cpp
    dll-loader.cpp

    api-set.hpp
    dll-loader.hpp
    )

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
    "--db ../../dlls.db dstng_firebird_d.dll"
)
