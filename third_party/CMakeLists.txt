set(CPYTHON_VERSION "3.13" CACHE INTERNAL "CPython version")
set(CPYTHON_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/cpython" CACHE INTERNAL "CPython source directory")
set(CPYTHON_INSTALL_DIR "${CMAKE_BINARY_DIR}/cpython" CACHE INTERNAL "CPython installation directory")
set(CPYTHON_HEADER_DIR "${CPYTHON_INSTALL_DIR}/include/python${CPYTHON_VERSION}" CACHE INTERNAL "CPython include directory")
set(CPYTHON_SHARED_LIB "${CPYTHON_INSTALL_DIR}/lib/libpython${CPYTHON_VERSION}.so" CACHE FILEPATH "CPython shared library")
set(CPYTHON_BINARY "${CPYTHON_INSTALL_DIR}/bin/python3" CACHE FILEPATH "CPython binary")
set(CPYTHON_VENV "${CPYTHON_INSTALL_DIR}/venv" CACHE FILEPATH "CPython virtual environment")

add_custom_command(
        OUTPUT ${CPYTHON_SHARED_LIB}
        COMMAND ./configure --enable-shared --prefix=${CPYTHON_INSTALL_DIR}
        COMMAND make -j$(nproc) install
        COMMAND patchelf --set-rpath '$$ORIGIN/../lib/' ${CPYTHON_BINARY}
        COMMAND ${CPYTHON_BINARY} -m venv ${CPYTHON_VENV}
        WORKING_DIRECTORY ${CPYTHON_SRC_DIR})

add_custom_target(
        cpython
        DEPENDS ${CPYTHON_SHARED_LIB})