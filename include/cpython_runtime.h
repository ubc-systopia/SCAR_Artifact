#pragma once

#include <stdint.h>

void cpython_eval_loop(char* file, uint32_t iterations);

void cpython_init(char *file);

void cpython_pow_set_key(const char *path);

void cpython_free();
