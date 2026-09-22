#pragma once

#include <stdint.h>

#define CPYTHON_EXTRA_WAITING_TIME (40000)

void cpython_eval_loop(char *file, uint32_t iterations);

void cpython_init(char *file);

void cpython_pow_set_key(const char *path);

void cpython_free();
