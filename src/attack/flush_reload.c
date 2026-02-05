#include "flush_reload.h"

#define MFENCE() asm volatile("mfence" : : : "memory")

uint64_t FR_wait(uint64_t waiting_time) {
    MFENCE();
    uint64_t tsc0 = rdtscp();
    uint64_t tsc1 = tsc0;
    while (tsc1 - tsc0 < waiting_time) {
        tsc1 = rdtscp();
    }
    return tsc1;
}

