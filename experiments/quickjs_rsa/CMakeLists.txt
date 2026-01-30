add_executable(openpgp_rsa openpgp_rsa.c)

target_link_libraries(openpgp_rsa PRIVATE utils prime_probe quickjs_runtime)
