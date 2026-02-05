cmake_minimum_required(VERSION 3.22)
project(SCAR_Artifact C CXX)

set(CMAKE_C_STANDARD 11)

set(CMAKE_C_FLAGS_DEBUG "-g -O1")
set(CMAKE_CXX_FLAGS_DEBUG "-g -O1")

add_definitions(-DICELAKE)

file(COPY setup.sh DESTINATION ${CMAKE_BINARY_DIR})
execute_process(COMMAND bash -c ./setup.sh)

set(INCLUDE_DIR ${CMAKE_SOURCE_DIR}/include CACHE FILEPATH "Common include directory")
include_directories(${INCLUDE_DIR})

add_subdirectory(third_party)
add_subdirectory(src)
add_subdirectory(experiments)
