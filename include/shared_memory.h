#pragma once

#include <pthread.h>
#include <stdint.h>

#define QUICKJS_PROJ_ID (100)
#define CPYTHON_PROJ_ID (200)
#define V8_PROJ_ID      (300)

typedef enum sync_ctx_action_t {
    SYNC_CTX_UNDEFINED,
    SYNC_CTX_START,
    SYNC_CTX_PROBE,
    SYNC_CTX_PAUSE,
    SYNC_CTX_SET_KEY,
    SYNC_CTX_EXIT,
} sync_ctx_action_t;

static inline const char *sync_ctx_action_name(sync_ctx_action_t action) {
    switch (action) {
        case SYNC_CTX_UNDEFINED: return "UNDEFINED";
        case SYNC_CTX_START:     return "START";
        case SYNC_CTX_PROBE:     return "PROBE";
        case SYNC_CTX_PAUSE:     return "PAUSE";
        case SYNC_CTX_SET_KEY:   return "SET_KEY";
        case SYNC_CTX_EXIT:      return "EXIT";
        default:                 return "UNKNOWN";
    }
}

typedef struct sync_ctx_t {
    pthread_barrier_t* barrier;
    pthread_mutex_t* mutex;
    sync_ctx_action_t* action;
    uint8_t *data;
} sync_ctx_t;

extern sync_ctx_t sync_ctx;
extern const size_t sync_ctx_data_size;

void init_sync_ctx(int proj_id);

void free_sync_ctx(int proj_id);

void reset_sync_ctx(int proj_id);

sync_ctx_action_t sync_ctx_get_action(void);

void sync_ctx_set_action(sync_ctx_action_t action);
