cmake_minimum_required(VERSION 3.22)
project(SCAR_Artifact C CXX)

set(CMAKE_C_STANDARD 11)

set(CMAKE_C_FLAGS_DEBUG "-g -O1")
set(CMAKE_CXX_FLAGS_DEBUG "-g -O1")

add_definitions(-DICELAKE)

# The V8 runtime and the two V8 case studies (v8_ecdh, v8_constant_time_js)
# are the slowest part of a first build, so they can be switched off on a
# machine that only runs the QuickJS and CPython experiments. Default ON:
# with it OFF, src/runtime/v8 is skipped and those experiments cannot link.
option(SCAR_ENABLE_V8 "Build the V8 runtime and the V8 case studies" ON)

file(COPY setup.sh DESTINATION ${CMAKE_BINARY_DIR})
execute_process(COMMAND bash -c ./setup.sh)

set(INCLUDE_DIR ${CMAKE_SOURCE_DIR}/include CACHE FILEPATH "Common include directory")
include_directories(${INCLUDE_DIR})

add_subdirectory(third_party)
add_subdirectory(src)
add_subdirectory(experiments)
