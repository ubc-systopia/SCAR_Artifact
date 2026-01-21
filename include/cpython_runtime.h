#pragma once

#include <stdint.h>

#define CPYTHON_PROJ_ID (200)

void cpython_eval_loop(char* file, uint32_t iterations);

void cpython_init(char *file);

void cpython_free();

