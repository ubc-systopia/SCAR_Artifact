add_executable(quickjs_rsa quickjs_rsa.c)

target_link_libraries(quickjs_rsa PRIVATE utils prime_probe quickjs_runtime)

add_executable(quickjs_rsa_key_pool quickjs_rsa_key_pool.c)

target_link_libraries(quickjs_rsa_key_pool PRIVATE utils prime_probe quickjs_runtime)
