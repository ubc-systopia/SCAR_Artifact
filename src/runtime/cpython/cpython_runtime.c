#include "cpython_runtime.h"

#include "config.h"
#include "log.h"
#include "Python.h"
#include "shared_memory.h"

#define PATH_LEN (256)

sync_ctx_t sync_ctx;

void cpython_init(char *file) {
    PyConfig config;
    char path[PATH_LEN];

    PyConfig_InitIsolatedConfig(&config);

    snprintf(path, PATH_LEN, "%s/build/cpython/venv/bin/python", get_config()->project_root);
    PyConfig_SetBytesString(&config, &config.executable, path);

    PyStatus status = Py_InitializeFromConfig(&config);
    PyConfig_Clear(&config);

    if (PyStatus_Exception(status)) {
        log_error("Failed to set up CPython environment in %s: %s", status.func,
                  status.err_msg);
        Py_ExitStatusException(status);
    }

    FILE* fp = fopen(file, "r");
    if (fp == NULL) {
        log_error("Failed to read CPython init file: %s", file);
        exit(1);
    }

    int res = PyRun_SimpleFile(fp, file);
    if (res != 0) {
        log_error("Failed to set up initialize CPython context", status.func, status.err_msg);
        exit(1);
    }
}

void cpython_free() {
    Py_Finalize();
}

void cpython_eval_loop(char* file, uint32_t iterations) {
    /* pin_cpu(pinned_cpu0); */

    log_info("Start cpython eval loop");

    reset_sync_ctx(CPYTHON_PROJ_ID);

    cpython_init(file);
    PyObject* module = PyImport_ImportModule("__main__");
    PyObject* test = PyObject_GetAttrString(module, "test");
    PyObject* probe = PyObject_GetAttrString(module, "probe");

    pthread_barrier_wait(sync_ctx.barrier);

    do {
        sync_ctx_action_t action = sync_ctx_get_action();
        uint64_t tsc = rdtscp();

        if (action == SYNC_CTX_START) {
            assert(test != NULL);
            for (int i = 0; i < iterations; i++) {
                PyObject *ret = PyObject_CallNoArgs(test);

                assert(ret != NULL);
                PyObject tmp = *ret;
                Py_XDECREF(ret);

                while (rdtscp() - tsc < 20000) {}
            }
        } else {
            assert(probe != NULL);
            PyObject *arg = PyLong_FromLong(*sync_ctx.data);
            for (int i = 0; i < iterations; i++) {
                PyObject *ret = PyObject_CallOneArg(probe, arg);

                assert(ret != NULL);
                PyObject tmp = *ret;
                Py_XDECREF(ret);

                while (rdtscp() - tsc < 20000) {}
            }
        }

        sync_ctx_set_action(SYNC_CTX_PAUSE);
        pthread_barrier_wait(sync_ctx.barrier);

        pthread_barrier_wait(sync_ctx.barrier);
    } while (sync_ctx_get_action() != SYNC_CTX_EXIT);

    Py_XDECREF(probe);
    Py_XDECREF(test);
    Py_DECREF(module);

    cpython_free();
}