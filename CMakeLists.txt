cmake_minimum_required(VERSION 3.27)
project(MemoryModulePP LANGUAGES CXX)

###############
# ASI default settings
list(APPEND CMAKE_MODULE_PATH "$ENV{ASV_CMAKE}")
include(asv_cmake_defaults)
asv_cmake_defaults( )
###############

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# add _d to debug targets
SET(CMAKE_DEBUG_POSTFIX _d)

# build spec done in subdirectories
add_subdirectory(3rdparty)
include_directories(${CMAKE_SOURCE_DIR}/3rdparty/phnt/include)
add_subdirectory(a)
add_subdirectory(MemoryModule)
add_subdirectory(test)
add_subdirectory(winhttp)
