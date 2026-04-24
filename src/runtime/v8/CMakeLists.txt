set(CMAKE_CXX_STANDARD 20)

add_library(v8_runtime STATIC v8_runtime.cc)

# ---------- v8_runtime ----------
target_include_directories(v8_runtime PUBLIC
	${CMAKE_SOURCE_DIR}/third_party/v8/
	${CMAKE_SOURCE_DIR}/third_party/v8/include
)

target_compile_options(v8_runtime PUBLIC
	-fno-rtti
	-pthread
	-DV8_COMPRESS_POINTERS
	-DV8_ENABLE_SANDBOX
	-DV8_ENABLE_CHECKS
)

add_dependencies(v8_runtime v8)

target_link_libraries(v8_runtime PUBLIC
	${V8_STATIC_LIB}
	dl
	utils
)

target_link_options(v8_runtime PUBLIC -fuse-ld=lld)
