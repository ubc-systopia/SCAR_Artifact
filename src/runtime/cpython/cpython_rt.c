#include "cpython_runtime.h"

#include <stdio.h>

#include "config.h"
#include "log.h"
#include "arch.h"
#include "fs.h"

void cpython_run(char *eval_file, uint32_t iterations) {
    config_t *cfg = get_config();
    char filepath[256];
    snprintf(filepath, sizeof(filepath), "%s/%s", cfg->project_root, eval_file);
    if (path_exists(eval_file)) {
        cpython_eval_loop(eval_file, iterations);
    } else if (path_exists(filepath)) {
        cpython_eval_loop(filepath, iterations);
    } else {
        log_error("Eval file %s not found", eval_file);
    }
}

int main(int argc, char *argv[]) {
    pin_cpu(pinned_cpu2);
    if (argc >= 2) {
        uint32_t iterations = 0;
        if (sscanf(argv[2], "%u", &iterations) == 1 && iterations > 0) {
            cpython_run(argv[1], iterations);
        } else {
            log_error("Invalid number of iterations");
        }
    } else {
        log_error("No eval file found");
    }
    return 0;
}
