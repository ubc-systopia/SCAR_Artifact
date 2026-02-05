add_library(cpython_runtime OBJECT cpython_runtime.c ${INCLUDE_DIR}/cpython_runtime.h)
add_dependencies(cpython_runtime cpython)
target_link_libraries(cpython_runtime PUBLIC ${CPYTHON_SHARED_LIB} utils)
target_include_directories(cpython_runtime PUBLIC ${CPYTHON_HEADER_DIR})

add_executable(cpython_rt cpython_rt.c)
target_link_libraries(cpython_rt PRIVATE cpython_runtime utils)