add_executable(openpgp_rsa openpgp_rsa.c)

target_link_libraries(openpgp_rsa PRIVATE utils prime_probe quickjs_runtime)


add_executable(pp_test pp_test.c)

target_link_libraries(pp_test PRIVATE utils prime_probe)
