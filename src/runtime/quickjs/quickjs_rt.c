#include "quickjs_runtime.h"

#include "config.h"
#include "log.h"
#include "arch.h"
#include "fs.h"

void quickjs_run(char *eval_file) {
    JSRuntime *rt = NULL;
    JSContext *ctx = NULL;
    config_t *cfg = get_config();
    char filepath[256];
    snprintf(filepath, sizeof(filepath), "%s/%s", cfg->project_root, eval_file);
    if (path_exists(eval_file)) {
        quickjs_eval_buf_loop(rt, ctx, eval_file);
    } else if (path_exists(filepath)) {
        quickjs_eval_buf_loop(rt, ctx, filepath);
    } else {
        log_error("Eval file %s not found", eval_file);
    }
}

int main(int argc, char *argv[]) {
    /* iso_pin_cpu(pinned_cpu2); */
    if (argc >= 1) {
        quickjs_run(argv[1]);
    } else {
        log_error("Not eval file found");
    }
    return 0;
}
