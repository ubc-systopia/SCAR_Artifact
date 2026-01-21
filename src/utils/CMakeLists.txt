add_library(utils OBJECT
        arch.c ${INCLUDE_DIR}/arch.h
        cache.c ${INCLUDE_DIR}/cache.h
        config.c ${INCLUDE_DIR}/config.h
        fs.c ${INCLUDE_DIR}/fs.h
        log.c ${INCLUDE_DIR}/log.h
        shared_memory.c ${INCLUDE_DIR}/shared_memory.h)