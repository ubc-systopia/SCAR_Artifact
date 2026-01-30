#include "shared_memory.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/stat.h>

#include "log.h"

#define BARRIER_PROJ_ID (0)
#define MUTEX_PROJ_ID (1)
#define ACTION_PROJ_ID (2)
#define DATA_PROJ_ID (2)

const size_t sync_ctx_data_size = 1024;

pthread_barrier_t *shm_create_barrier(int proj_id) {
    key_t shmkey = ftok("/dev/null", proj_id + BARRIER_PROJ_ID);
    int shmid = shmget(shmkey, sizeof(pthread_barrier_t), 0644);
    log_info("shmkey for barrier = %d, shmid: %d", shmkey, shmid);
    pthread_barrier_t *barrier = NULL;
    if (shmid == -1) {
        log_info("barrier created");
        shmid = shmget(shmkey, sizeof(pthread_barrier_t), 0644 | IPC_CREAT);
        if (shmid == -1) {
            log_error("shmget: %s", strerror(errno));
            exit(EXIT_FAILURE);
        }
        barrier = (pthread_barrier_t *) shmat(shmid, NULL, 0);

        pthread_barrierattr_t barrier_attr;
        pthread_barrierattr_setpshared(&barrier_attr, PTHREAD_PROCESS_SHARED);
        pthread_barrier_init(barrier, &barrier_attr, 2);
    } else {
        log_info("barrier exists");
        barrier = (pthread_barrier_t *) shmat(shmid, NULL, 0);
    }

    return barrier;
}

void shm_release_barrier(int proj_id) {
    key_t shmkey = ftok("/dev/null", proj_id + BARRIER_PROJ_ID);
    int shmid = shmget(shmkey, sizeof(pthread_barrier_t), 0644);
    if (shmid != -1) {
        if (shmctl(shmid, IPC_RMID, NULL) == -1) {
            log_error("shmctl failed: %s", strerror(errno));
            exit(1);
        }
    }
}

pthread_mutex_t* shm_create_mutex(int proj_id) {
    key_t shmkey = ftok("/dev/null", proj_id + MUTEX_PROJ_ID);
    int shmid = shmget(shmkey, sizeof(pthread_mutex_t), 0644);
    pthread_mutex_t* mutex = NULL;
    if (shmid == -1) {
        shmid = shmget(shmkey, sizeof(pthread_mutex_t), 0644 | IPC_CREAT);
        if (shmid == -1) {
            log_error("shmget: %s", strerror(errno));
            exit(EXIT_FAILURE);
        }
        mutex = (pthread_mutex_t*)shmat(shmid, NULL, 0);

        pthread_mutexattr_t mutex_attr;
        pthread_mutexattr_init(&mutex_attr);
        pthread_mutexattr_setpshared(&mutex_attr, PTHREAD_PROCESS_SHARED);
        pthread_mutex_init(mutex, &mutex_attr);
    } else {
        mutex = (pthread_mutex_t*)shmat(shmid, NULL, 0);
    }
    return mutex;
}

void shm_release_mutex(int proj_id) {
    key_t shmkey = ftok("/dev/null", proj_id + MUTEX_PROJ_ID);
    int shmid = shmget(shmkey, sizeof(pthread_mutex_t), 0644);
    if (shmid > 0) {
        if (shmctl(shmid, IPC_RMID, NULL) == -1) {
            log_error("shmctl failed: %s", strerror(errno));
            exit(1);
        }
    }
}


void* shm_alloc(const char* name, int proj_id, size_t size) {
    char filename[256];
    sprintf(filename, "/tmp/%s", name);

    struct stat buffer;
    if (stat(filename, &buffer) != 0) {
        FILE* file = fopen(filename, "w");
        fclose(file);
    }

    key_t key = ftok(filename, proj_id + DATA_PROJ_ID);  // Generate the same unique key
    int shmid = shmget(key, size, 0644);  // Get shared memory

    if (shmid == -1) {
        shmid = shmget(key, size, 0644 | IPC_CREAT);
        if (shmid == -1) {
            log_error("shmget: %s", strerror(errno));
            exit(EXIT_FAILURE);
        }
    }

    void* sm = shmat(shmid, NULL, 0);  // Attach to shared memory
    return sm;
}

void shm_release(const char* name, int proj_id, size_t size) {
    char filename[256];
    sprintf(filename, "/tmp/%s", name);

    struct stat buffer;
    if (stat(filename, &buffer) == 0) {
        key_t key = ftok(filename, proj_id + DATA_PROJ_ID);  // Generate the same unique key
        int shmid = shmget(key, size, 0644);  // Get shared memory

        if (shmid > 0) {
            if (shmctl(shmid, IPC_RMID, NULL) == -1) {
                log_error("shmctl failed: %s", strerror(errno));
                exit(1);
            }
        }
    }
}

void init_sync_ctx(int proj_id) {
    const int k = 100;
    int barrier_id = k * proj_id + BARRIER_PROJ_ID;
    int mutex_id = k * proj_id + MUTEX_PROJ_ID;
    int action_id = k * proj_id + ACTION_PROJ_ID;
    int data_id = k * proj_id + DATA_PROJ_ID;

    sync_ctx.barrier = shm_create_barrier(barrier_id);
    sync_ctx.mutex = shm_create_mutex(mutex_id);
    sync_ctx.action = shm_alloc("sync_ctx_action", action_id, sizeof(sync_ctx_action_t));
    sync_ctx.data = (uint8_t *) shm_alloc("sync_ctx_data", data_id, sizeof(uint8_t)*sync_ctx_data_size);
}

void free_sync_ctx(int proj_id) {
    const int k = 100;

    int barrier_id = k * proj_id + BARRIER_PROJ_ID;
    int mutex_id = k * proj_id + MUTEX_PROJ_ID;
    int action_id = k * proj_id + ACTION_PROJ_ID;
    int data_id = k * proj_id + DATA_PROJ_ID;

    shm_release_barrier(barrier_id);
    shm_release_mutex(mutex_id);
    shm_release("sync_ctx_action", action_id, sizeof(sync_ctx_action_t));
    shm_release("sync_ctx_data", data_id, sizeof(uint8_t)*sync_ctx_data_size);
}

void reset_sync_ctx(int proj_id) {
    free_sync_ctx(proj_id);
    init_sync_ctx(proj_id);
}


sync_ctx_action_t sync_ctx_get_action(void) {
    pthread_mutex_lock(sync_ctx.mutex);
    sync_ctx_action_t action = *sync_ctx.action;
    pthread_mutex_unlock(sync_ctx.mutex);
    return action;
}

void sync_ctx_set_action(sync_ctx_action_t action) {
    pthread_mutex_lock(sync_ctx.mutex);
    *sync_ctx.action = action;
    pthread_mutex_unlock(sync_ctx.mutex);
}
