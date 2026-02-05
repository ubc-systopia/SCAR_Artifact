#include "cpython_runtime.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include "config.h"
#include "log.h"
#include "arch.h"
#include "fs.h"

void cpython_run(char *eval_file, uint64_t iterations) {
    config_t *cfg = get_config();
    char filepath[256];
    snprintf(filepath, sizeof(filepath), "%s/%s", cfg->project_root, eval_file);

    if (path_exists(eval_file)) {
        log_info("Running script: %s %lu time(s)", eval_file, iterations);
        cpython_eval_loop(eval_file, iterations);
    } else {
        log_error("Eval file %s not found", eval_file);
    }
}

int main(int argc, char *argv[]) {
    pin_cpu(pinned_cpu2);

    if (argc >= 3) {
        char *endptr = NULL;
        errno = 0;
        const uint64_t iterations = strtoull(argv[2], &endptr, 10);
        if (errno == 0 && endptr != argv[2] && *endptr == '\0') {
            cpython_run(argv[1], iterations);
        } else {
            log_error("Invalid number of iterations");
        }
    } else {
        log_error("Incorrect arguments");
    }
    return 0;
}
