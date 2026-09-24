add_executable(quickjs_jpeg quickjs_jpeg.c)

target_link_libraries(quickjs_jpeg PRIVATE utils prime_probe quickjs_runtime)

add_executable(quickjs_jpeg_bc quickjs_jpeg_bc.c)
target_link_libraries(quickjs_jpeg_bc PRIVATE utils prime_probe quickjs_runtime)
