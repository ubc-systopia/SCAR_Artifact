#include "quickjs_runtime.h"

#include <string.h>

#include "arch.h"
#include "cache.h"
#include "log.h"
#include "quickjs/quickjs-libc.h"
#include "shared_memory.h"

sync_ctx_t sync_ctx;

JSContext* JS_NewCustomContext(JSRuntime* rt) {
    JSContext* ctx;
    ctx = JS_NewContextRaw(rt);
    if (!ctx)
        return NULL;
    /* system modules */
    JS_AddIntrinsicBaseObjects(ctx);
    JS_AddIntrinsicDate(ctx);
    JS_AddIntrinsicEval(ctx);
    JS_AddIntrinsicStringNormalize(ctx);
    JS_AddIntrinsicRegExp(ctx);
    JS_AddIntrinsicJSON(ctx);
    JS_AddIntrinsicProxy(ctx);
    JS_AddIntrinsicMapSet(ctx);
    JS_AddIntrinsicTypedArrays(ctx);
    JS_AddIntrinsicPromise(ctx);
    JS_AddIntrinsicBigInt(ctx);
    js_init_module_std(ctx, "std");
    js_init_module_os(ctx, "os");
    return ctx;
}

void quickjs_init(JSRuntime **rt, JSContext **ctx) {
    *rt = JS_NewRuntime();
    js_std_set_worker_new_context_func(JS_NewCustomContext);
    js_std_init_handlers(*rt);
    *ctx = JS_NewCustomContext(*rt);
    JS_SetModuleLoaderFunc(*rt, NULL, js_module_loader, NULL);
    js_std_add_helpers(*ctx, 0, NULL);
}

void quickjs_free(JSRuntime* rt, JSContext* ctx) {
    js_std_free_handlers(rt);
    JS_FreeContext(ctx);
    JS_FreeRuntime(rt);
}

void quickjs_eval_buf_loop(JSRuntime* rt,
                           JSContext* ctx,
                           const char* eval_file) {
    /* pin_cpu(pinned_cpu0); */

    log_info("Start quickjs eval loop");

    reset_sync_ctx(QUICKJS_PROJ_ID);

    quickjs_init(&rt, &ctx);

    size_t buf_len;
    uint8_t *buf = js_load_file(ctx, &buf_len, eval_file);

    pthread_barrier_wait(sync_ctx.barrier);

    do {
        js_std_eval_buf(ctx, buf, buf_len, eval_file, 1);

        sync_ctx_set_action(SYNC_CTX_PAUSE);
        pthread_barrier_wait(sync_ctx.barrier);

        pthread_barrier_wait(sync_ctx.barrier);
    } while (sync_ctx_get_action() != SYNC_CTX_EXIT);

    quickjs_free(rt, ctx);
}

