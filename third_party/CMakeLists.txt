# QuickJS
set(QUICKJS_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/quickjs" CACHE FILEPATH "QuickJS source directory")
set(QUICKJS_INSTALL_DIR "${CMAKE_BINARY_DIR}/quickjs" CACHE FILEPATH "QuickJS installation directory")
set(QUICKJS_HEADER_DIR "${QUICKJS_INSTALL_DIR}/include" CACHE FILEPATH "QuickJS include directory")
set(QUICKJS_SHARED_LIB "${QUICKJS_INSTALL_DIR}/lib/quickjs/libquickjs.so" CACHE FILEPATH "QuickJS shared library")

add_custom_command(
        OUTPUT ${QUICKJS_SHARED_LIB}
        COMMAND PREFIX=${QUICKJS_INSTALL_DIR} $(MAKE) -j$(nproc) install
        WORKING_DIRECTORY ${QUICKJS_SRC_DIR})

add_custom_target(quickjs DEPENDS ${QUICKJS_SHARED_LIB})


# CPython
set(CPYTHON_VERSION "3.13" CACHE INTERNAL "CPython version")
set(CPYTHON_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/cpython" CACHE FILEPATH "CPython source directory")
set(CPYTHON_INSTALL_DIR "${CMAKE_BINARY_DIR}/cpython" CACHE FILEPATH "CPython installation directory")
set(CPYTHON_HEADER_DIR "${CPYTHON_INSTALL_DIR}/include/python${CPYTHON_VERSION}" CACHE FILEPATH "CPython include directory")
set(CPYTHON_SHARED_LIB "${CPYTHON_INSTALL_DIR}/lib/libpython${CPYTHON_VERSION}.so" CACHE FILEPATH "CPython shared library")
set(CPYTHON_BINARY "${CPYTHON_INSTALL_DIR}/bin/python3" CACHE FILEPATH "CPython binary")
set(CPYTHON_VENV "${CPYTHON_INSTALL_DIR}/venv" CACHE FILEPATH "CPython virtual environment")

add_custom_command(
        OUTPUT ${CPYTHON_SHARED_LIB}
        COMMAND ./configure --enable-shared --prefix=${CPYTHON_INSTALL_DIR}
        COMMAND $(MAKE) -j$(nproc) install
        COMMAND patchelf --set-rpath '$$ORIGIN/../lib/' ${CPYTHON_BINARY}
        COMMAND ${CPYTHON_BINARY} -m venv ${CPYTHON_VENV}
        WORKING_DIRECTORY ${CPYTHON_SRC_DIR})

add_custom_target(cpython DEPENDS ${CPYTHON_SHARED_LIB})

# LLCFeasible
add_subdirectory(LLCFeasible)

# V8
message("Fetching V8...")
execute_process(
        COMMAND ${CMAKE_COMMAND} -E env PATH=${CMAKE_CURRENT_SOURCE_DIR}/depot_tools:$ENV{PATH} fetch v8
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
message("Checking out target commit...")
execute_process(
        COMMAND git checkout 13.1-lkgr
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/v8)
message("Syncing V8...")
execute_process(
        COMMAND ${CMAKE_COMMAND} -E env PATH=${CMAKE_CURRENT_SOURCE_DIR}/depot_tools:$ENV{PATH} gclient sync -D
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/v8)
message("Configuring V8...")
set(GN_ARGS "
dcheck_always_on = false
is_component_build = false
use_custom_libcxx = false
v8_monolithic = true
v8_use_external_startup_data = false
is_debug = true
symbol_level = 2
target_cpu = \"x64\"
v8_enable_debugging_features = true
v8_enable_backtrace = true
v8_enable_fast_mksnapshot = true
v8_enable_slow_dchecks = true
v8_optimized_debug = false
v8_expose_symbols = true
v8_symbol_level = 2
cppgc_enable_object_names = true
v8_enable_disassembler = true
v8_enable_gdbjit = true
")
string(REPLACE "\n" " " GN_ARGS "${GN_ARGS}")
execute_process(
        COMMAND ${CMAKE_COMMAND} -E env PATH=${CMAKE_CURRENT_SOURCE_DIR}/depot_tools:$ENV{PATH} gn gen out.gn/x64.debug --args=${GN_ARGS}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/v8)

set(V8_STATIC_LIB
	"${CMAKE_CURRENT_SOURCE_DIR}/v8/out.gn/x64.debug/obj/libv8_monolith.a"
	"${CMAKE_CURRENT_SOURCE_DIR}/v8/out.gn/x64.debug/obj/libv8_libbase.a"
	"${CMAKE_CURRENT_SOURCE_DIR}/v8/out.gn/x64.debug/obj/libv8_libplatform.a"
	CACHE FILEPATH "V8 static libraries")

add_custom_command(
        OUTPUT ${V8_STATIC_LIB}
        COMMAND ${CMAKE_COMMAND} -E env PATH=${CMAKE_CURRENT_SOURCE_DIR}/depot_tools:$ENV{PATH} ninja -C out.gn/x64.debug
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/v8)

add_custom_target(v8 DEPENDS ${V8_STATIC_LIB})
