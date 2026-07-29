#!/usr/bin/env python3
import pathlib
import sys


def replace_once(text, old, new, label):
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected one {label} insertion point, found {count}")
    return text.replace(old, new, 1)


path = pathlib.Path(sys.argv[1])
source = path.read_text()

source = replace_once(
    source,
    "#endif\n\n#define OPTIMIZE         1\n#define SHORT_OPCODES    1",
    "#endif\n#ifdef OPCODE_TIMING\n#include <x86intrin.h>\n#endif\n\n"
    "#define OPTIMIZE         1\n#define SHORT_OPCODES    1",
    "header",
)

source = replace_once(
    source,
    "#ifdef LLCT_INST\nvoid* quickjs_dispatch_table[256];\n#endif\n\n\n#ifdef LLCT_GRTH",
    """#ifdef LLCT_INST
void* quickjs_dispatch_table[256];
#endif

#ifdef OPCODE_TIMING
static FILE *opcode_timing_file;
static const char * const opcode_timing_names[256] = {
#define DEF(id, size, n_pop, n_push, f) [OP_ ## id] = #id,
#if SHORT_OPCODES
#define def(id, size, n_pop, n_push, f)
#else
#define def(id, size, n_pop, n_push, f) [OP_ ## id] = #id,
#endif
#include "quickjs-opcode.h"
#undef def
#undef DEF
};

static FILE *opcode_timing_output(void)
{
    const char *path;
    if (opcode_timing_file)
        return opcode_timing_file;
    path = getenv("QJS_OPCODE_TIMING_OUT");
    if (!path || !path[0])
        path = "opcode_timing.csv";
    opcode_timing_file = fopen(path, "w");
    if (!opcode_timing_file) {
        perror(path);
        exit(1);
    }
    fputs("condition,handler,cycles\\n", opcode_timing_file);
    return opcode_timing_file;
}
#endif

#ifdef LLCT_GRTH""",
    "trace support",
)

source = replace_once(
    source,
    "    size_t alloca_size;\n\n#if !DIRECT_DISPATCH",
    """    size_t alloca_size;
#ifdef OPCODE_TIMING
    int opcode_timing_active = 0;
    int opcode_timing_previous = -1;
    int64_t opcode_timing_condition = 0;
    uint64_t opcode_timing_start = 0;
    uint32_t opcode_timing_aux;
#endif

#if !DIRECT_DISPATCH""",
    "local state",
)

source = replace_once(
    source,
    "#define SWITCH(pc)      goto *dispatch_table[opcode = *pc++];\n#endif\n#define CASE(op)",
    r'''#ifdef OPCODE_TIMING
#define SWITCH(pc) {                                                      \
        uint64_t opcode_timing_now;                                      \
        opcode = *pc++;                                                  \
        if (opcode_timing_active) {                                      \
            opcode_timing_now = __rdtscp(&opcode_timing_aux);            \
            if (opcode_timing_previous >= 0)                             \
                fprintf(opcode_timing_output(), "%s,%s,%lu\n",          \
                        opcode_timing_condition ? "true" : "false",     \
                        opcode_timing_names[opcode_timing_previous] ?     \
                            opcode_timing_names[opcode_timing_previous] : \
                            "unknown",                                  \
                        (unsigned long)(opcode_timing_now -               \
                                        opcode_timing_start));           \
            opcode_timing_previous = opcode;                             \
            opcode_timing_start = __rdtscp(&opcode_timing_aux);          \
        }                                                                \
        goto *dispatch_table[opcode];                                    \
    }
#else
#define SWITCH(pc)      goto *dispatch_table[opcode = *pc++];
#endif
#endif
#define CASE(op)''',
    "dispatch",
)

source = replace_once(
    source,
    "    ctx = b->realm; /* set the current realm */\n\n restart:",
    """    ctx = b->realm; /* set the current realm */
#ifdef OPCODE_TIMING
    if (getenv("QJS_OPCODE_TIMING_OUT") && argc > 0) {
        if (argc == 4 && JS_IsBigInt(ctx, arg_buf[0]) &&
            JS_ToBigInt64(ctx, &opcode_timing_condition, arg_buf[0]) == 0)
            opcode_timing_active = 1;
    }
#endif

 restart:""",
    "activation",
)

source = replace_once(
    source,
    "    } else {\n    done:\n        if (unlikely(!list_empty(&sf->var_ref_list))) {",
    """    } else {
    done:
#ifdef OPCODE_TIMING
        if (opcode_timing_active && opcode_timing_previous >= 0) {
            uint64_t opcode_timing_end = __rdtscp(&opcode_timing_aux);
            fprintf(opcode_timing_output(), "%s,%s,%lu\\n",
                    opcode_timing_condition ? "true" : "false",
                    opcode_timing_names[opcode_timing_previous] ?
                        opcode_timing_names[opcode_timing_previous] : "unknown",
                    (unsigned long)(opcode_timing_end - opcode_timing_start));
            opcode_timing_active = 0;
        }
#endif
        if (unlikely(!list_empty(&sf->var_ref_list))) {""",
    "final handler",
)

path.write_text(source)
