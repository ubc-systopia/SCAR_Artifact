#pragma once

#include <pthread.h>
#include <stdint.h>

#define SHARED_DATA_SIZE (1024)

typedef enum sync_ctx_action_t {
    SYNC_CTX_UNDEFINED,
    SYNC_LOOP_START,
    SYNC_LOOP_PAUSE,
    SYNC_CTX_EXIT,
} sync_ctx_action_t;

typedef struct sync_ctx_t {
    pthread_barrier_t* barrier;
    pthread_mutex_t* mutex;
    sync_ctx_action_t* action;
    uint8_t (*data)[SHARED_DATA_SIZE];
} sync_ctx_t;

extern sync_ctx_t sync_ctx;

void init_sync_ctx(int proj_id);

void free_sync_ctx(int proj_id);

void reset_sync_ctx(int proj_id);

sync_ctx_action_t sync_ctx_get_action(void);

void sync_ctx_set_action(sync_ctx_action_t action);