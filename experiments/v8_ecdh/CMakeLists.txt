set(CMAKE_CXX_STANDARD 20)

add_executable(v8_ecdh_key_pool v8_ecdh_key_pool.cc)
target_link_libraries(v8_ecdh_key_pool PRIVATE v8_runtime utils prime_probe)
