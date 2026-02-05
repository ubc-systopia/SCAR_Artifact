#pragma once

#include <stdint.h>

#include "cache.h"
#include "Python.h"

#define CPYTHON_TARGET_CACHELINE(V)                                             \
    V(consume_zero, python_language_feature_targets[2], 1)         \
    V(absorb_window, python_language_feature_targets[3], 1)      \
    V(absorb_trailing, python_language_feature_targets[5], 1)

#define DECLARE_CACHE_LINE(NAME, BASE_ADDR, OFFSET) \
    uintptr_t target_##NAME;                        \
    uint64_t offset_##NAME;

#define TARGET_ADDRESS_OFFSET(NAME, BASE_ADDR, OFFSET) \
    target_##NAME = ((uintptr_t)(BASE_ADDR + OFFSET) & CACHE_LINE_MASK);
