cmake_minimum_required(VERSION 3.27)
project(MemoryModulePP LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# add _d to debug targets
SET(CMAKE_DEBUG_POSTFIX _d)

# build spec done in subdirectories
add_subdirectory(3rdparty)
add_subdirectory(MemoryModule)
add_subdirectory(test)
