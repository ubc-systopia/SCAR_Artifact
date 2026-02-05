add_executable(quickjs_jpeg quickjs_jpeg.c)

target_link_libraries(quickjs_jpeg PRIVATE utils prime_probe quickjs_runtime)
