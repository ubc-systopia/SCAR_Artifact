add_library(quickjs_runtime OBJECT quickjs_runtime.c ${INCLUDE_DIR}/quickjs_runtime.h)
add_dependencies(quickjs_runtime quickjs)
target_link_libraries(quickjs_runtime PUBLIC ${QUICKJS_SHARED_LIB} utils)
target_include_directories(quickjs_runtime PUBLIC ${QUICKJS_HEADER_DIR})

add_executable(quickjs_rt quickjs_rt.c)
target_link_libraries(quickjs_rt PRIVATE quickjs_runtime ${QUICKJS_SHARED_LIB} utils)