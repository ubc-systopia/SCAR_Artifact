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

target_link_libraries(v8_runtime PUBLIC
	"${CMAKE_SOURCE_DIR}/third_party/v8/out.gn/x64.debug/obj/libv8_monolith.a"
	"${CMAKE_SOURCE_DIR}/third_party/v8/out.gn/x64.debug/obj/libv8_libbase.a"
	"${CMAKE_SOURCE_DIR}/third_party/v8/out.gn/x64.debug/obj/libv8_libplatform.a"
	dl
	utils
)

target_link_options(v8_runtime PUBLIC -fuse-ld=lld)
