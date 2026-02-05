add_custom_target(cpython_pow_requirements
        COMMAND ${CPYTHON_VENV}/bin/python -m pip install -r ${CMAKE_CURRENT_SOURCE_DIR}/python/requirements.txt)
add_dependencies(cpython_pow_requirements cpython)

add_executable(cpython_pow cpython_pow.c cpython_pow.h)
add_dependencies(cpython_pow cpython cpython_pow_requirements)
target_link_libraries(cpython_pow PRIVATE ${CPYTHON_SHARED_LIB} utils flush_reload)
target_include_directories(cpython_pow PRIVATE ${CPYTHON_HEADER_DIR})
