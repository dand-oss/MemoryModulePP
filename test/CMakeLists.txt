cmake_minimum_required(VERSION 3.27)
project(mmtest LANGUAGES CXX)

# Define executable targets
set(static_exename "mmtest-static")
add_executable(${static_exename})

set(shared_exename "mmtest-shared")
add_executable(${shared_exename})

# sources
target_sources(${static_exename} PRIVATE test.cpp)
target_sources(${shared_exename} PRIVATE test.cpp)

# linking
target_link_libraries(${static_exename} PRIVATE
    MemoryModulePP-static
    lib_detours
)
target_link_libraries(${shared_exename} PRIVATE
    MemoryModulePP-shared
)
