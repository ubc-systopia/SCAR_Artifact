add_executable(openpgp_rsa openpgp_rsa.c)

target_link_libraries(openpgp_rsa PRIVATE utils prime_probe quickjs_runtime)

add_executable(openpgp_rsa_key_pool openpgp_rsa_key_pool.c)

target_link_libraries(openpgp_rsa_key_pool PRIVATE utils prime_probe quickjs_runtime)
