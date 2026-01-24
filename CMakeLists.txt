cmake_minimum_required(VERSION 3.22)
project(SCAR_Artifact C)

set(CMAKE_C_STANDARD 11)

execute_process(COMMAND bash -c setup.sh)

set(INCLUDE_DIR ${CMAKE_SOURCE_DIR}/include CACHE FILEPATH "Common include directory")
include_directories(${INCLUDE_DIR})

add_subdirectory(third_party)
add_subdirectory(src)
add_subdirectory(experiments)