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

# ---------- V8 ----------

set(V8_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/v8" CACHE FILEPATH "V8 source directory")
set(V8_DEPOT_TOOLS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/depot_tools" CACHE FILEPATH "depot_tools directory")
set(V8_GIT_REF "13.1-lkgr" CACHE STRING "V8 tag/branch to check out")
set(V8_OUT_SUBDIR "out.gn/x64.release" CACHE STRING "V8 build directory, relative to V8_SRC_DIR")
set(V8_OUT_DIR "${V8_SRC_DIR}/${V8_OUT_SUBDIR}" CACHE INTERNAL "V8 build directory (absolute)")

set(V8_NINJA_TARGETS v8_monolith v8_libbase v8_libplatform)

if(NOT EXISTS "${V8_SRC_DIR}")
    message("Fetching V8...")
    execute_process(
            COMMAND ${CMAKE_COMMAND} -E env PATH=${V8_DEPOT_TOOLS_DIR}:$ENV{PATH} fetch v8
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
    message("Checking out target commit...")
    execute_process(
            COMMAND git checkout ${V8_GIT_REF}
            WORKING_DIRECTORY ${V8_SRC_DIR})
    message("Syncing V8...")
    execute_process(
            COMMAND ${CMAKE_COMMAND} -E env PATH=${V8_DEPOT_TOOLS_DIR}:$ENV{PATH} gclient sync -D
            WORKING_DIRECTORY ${V8_SRC_DIR})
endif()

if(NOT EXISTS "${V8_OUT_DIR}/build.ninja")
    message("Configuring V8...")
    set(GN_ARGS "
    dcheck_always_on = false
    is_component_build = false
    use_custom_libcxx = false
    v8_monolithic = true
    v8_use_external_startup_data = false
    is_debug = false
    target_cpu = \"x64\"
    v8_enable_backtrace = false
    symbol_level = 0
    ")
    string(REPLACE "\n" " " GN_ARGS "${GN_ARGS}")
    execute_process(
            COMMAND ${CMAKE_COMMAND} -E env PATH=${V8_DEPOT_TOOLS_DIR}:$ENV{PATH} gn gen ${V8_OUT_SUBDIR} --args=${GN_ARGS}
            WORKING_DIRECTORY ${V8_SRC_DIR})
endif()

set(V8_STATIC_LIB
	"${V8_OUT_DIR}/obj/libv8_monolith.a"
	"${V8_OUT_DIR}/obj/libv8_libbase.a"
	"${V8_OUT_DIR}/obj/libv8_libplatform.a"
	CACHE INTERNAL "V8 static libraries")

set(V8_MISSING_LIBS "")
foreach(lib IN LISTS V8_STATIC_LIB)
    if(NOT EXISTS "${lib}")
        list(APPEND V8_MISSING_LIBS "${lib}")
    endif()
endforeach()

if(V8_MISSING_LIBS)
    message("Building V8 (missing: ${V8_MISSING_LIBS})")
    add_custom_command(
            OUTPUT ${V8_STATIC_LIB}
            COMMAND ${CMAKE_COMMAND} -E env PATH=${V8_DEPOT_TOOLS_DIR}:$ENV{PATH} ninja -C ${V8_OUT_SUBDIR} ${V8_NINJA_TARGETS}
            WORKING_DIRECTORY ${V8_SRC_DIR}
            COMMENT "Building V8 static libs: ${V8_NINJA_TARGETS}"
            USES_TERMINAL
            VERBATIM)

    add_custom_target(v8 DEPENDS ${V8_STATIC_LIB})
else()
    add_custom_target(v8)
endif()
