add_library(utils OBJECT
        arch.c ${INCLUDE_DIR}/arch.h
        cache.c ${INCLUDE_DIR}/cache.h
        config.c ${INCLUDE_DIR}/config.h
        fs.c ${INCLUDE_DIR}/fs.h
        log.c ${INCLUDE_DIR}/log.h
        dsp.c ${INCLUDE_DIR}/dsp.h
        shared_memory.c ${INCLUDE_DIR}/shared_memory.h)


find_package(PkgConfig REQUIRED)
pkg_search_module(FFTW REQUIRED fftw3 IMPORTED_TARGET)
include_directories(PkgConfig::FFTW)
target_link_libraries(utils PRIVATE m PkgConfig::FFTW)
