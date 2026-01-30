add_executable(jpeg_js jpeg_js.c)

target_link_libraries(jpeg_js PRIVATE utils prime_probe quickjs_runtime)
