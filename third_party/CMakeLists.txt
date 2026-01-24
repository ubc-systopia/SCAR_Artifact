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
        COMMAND ./configure --enable-shared --prefix=${CPYTHON_INSTALL_DIR} > /dev/null
        COMMAND $(MAKE) -j$(nproc) install > /dev/null
        COMMAND patchelf --set-rpath '$$ORIGIN/../lib/' ${CPYTHON_BINARY}
        COMMAND ${CPYTHON_BINARY} -m venv ${CPYTHON_VENV}
        WORKING_DIRECTORY ${CPYTHON_SRC_DIR})

add_custom_target(cpython DEPENDS ${CPYTHON_SHARED_LIB})
