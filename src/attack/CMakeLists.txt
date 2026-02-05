add_library(flush_reload OBJECT flush_reload.c ${INCLUDE_DIR}/flush_reload.h)

add_library(prime_probe OBJECT prime_probe.c LLCF.c ${INCLUDE_DIR}/prime_probe.h)
add_dependencies(prime_probe "CACHE")
target_include_directories(prime_probe PUBLIC ${CMAKE_SOURCE_DIR}/third_party/LLCFeasible/include)
target_link_libraries(prime_probe utils "CACHE")
