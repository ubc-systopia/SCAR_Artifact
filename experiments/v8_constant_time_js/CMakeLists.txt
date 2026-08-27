set(CMAKE_CXX_STANDARD 20)

add_executable(v8_ctjs_ecdh v8_ctjs_ecdh.cc)
target_link_libraries(v8_ctjs_ecdh PRIVATE v8_runtime utils flush_reload prime_probe)
