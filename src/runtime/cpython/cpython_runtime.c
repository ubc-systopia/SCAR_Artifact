#include "cpython_runtime.h"

#include "arch.h"
#include "config.h"
#include "log.h"
#include "Python.h"
#include "shared_memory.h"
#include <stdint.h>

#define PATH_LEN (256)

sync_ctx_t sync_ctx;

void cpython_init(char *file) {
    PyConfig config;
    char path[PATH_LEN];

    PyConfig_InitIsolatedConfig(&config);

    snprintf(path,
             PATH_LEN,
             "%s/build/cpython/venv/bin/python",
             get_config()->project_root);
    PyConfig_SetBytesString(&config, &config.executable, path);

    PyStatus status = Py_InitializeFromConfig(&config);
    PyConfig_Clear(&config);

    if (PyStatus_Exception(status)) {
        log_error("Failed to set up CPython environment in %s: %s",
                  status.func,
                  status.err_msg);
        Py_ExitStatusException(status);
    }

    FILE *fp = fopen(file, "r");
    if (fp == NULL) {
        log_error("Failed to read CPython init file: %s", file);
        exit(1);
    }

    int res = PyRun_SimpleFile(fp, file);
    if (res != 0) {
        log_error("Failed to set up initialize CPython context",
                  status.func,
                  status.err_msg);
        exit(1);
    }

    log_info("Python environment initialized successfully");
}

void cpython_free() {
    Py_Finalize();
}

void cpython_save_gt(const char *filename) {
    FILE *fp = fopen(filename, "w");
    if (fp == NULL) {
        log_error("Error opening ground truth file %s", filename);
        return;
    }

    for (uint16_t j = 0; j < python_opcode_log_ctr; ++j) {
        uint64_t time = python_opcode_log[j][0];
        uint64_t opcode = python_opcode_log[j][1];
        if (opcode == INSTR_POW_ZERO)
            fprintf(fp, "0:%lu:zero\n", time);
        if (opcode == INSTR_POW_WINDOW)
            fprintf(fp, "1:%lu:window\n", time);
        if (opcode == INSTR_POW_TRAILING)
            fprintf(fp, "2:%lu:trailing\n", time);
    }

    fclose(fp);
}

void cpython_eval_loop(char *file, uint32_t iterations) {
    uint32_t extra_waiting_time = 20000;

    log_info("Start cpython eval loop");

    reset_sync_ctx(CPYTHON_PROJ_ID);

    cpython_init(file);
    PyObject *module = PyImport_ImportModule("__main__");
    PyObject *test = PyObject_GetAttrString(module, "test");
    if (!test)
        PyErr_Clear();
    PyObject *probe = PyObject_GetAttrString(module, "probe");
    if (!probe)
        PyErr_Clear();

    // Signal init done
    pthread_barrier_wait(sync_ctx.barrier);

    log_info("Wait for attacker initialization");

    // Wait for attacker process
    pthread_barrier_wait(sync_ctx.barrier);

    do {
        python_opcode_log_ctr = 0;
        sync_ctx_action_t action = sync_ctx_get_action();
        uint64_t tsc = rdtscp();

        if (action == SYNC_CTX_START) {
            assert(test != NULL);
            for (int i = 0; i < iterations; i++) {
                tsc = rdtscp();
                PyObject *ret = PyObject_CallNoArgs(test);

                assert(ret != NULL);
                PyObject tmp = *ret;
                Py_XDECREF(ret);

                while (rdtscp() - tsc < extra_waiting_time) {
                }
            }
        } else {
            assert(probe != NULL);
            PyObject *arg = PyLong_FromUnsignedLong(*sync_ctx.data);
            for (int i = 0; i < iterations; i++) {
                tsc = rdtscp();
                PyObject *ret = PyObject_CallOneArg(probe, arg);

                assert(ret != NULL);
                PyObject tmp = *ret;
                Py_XDECREF(ret);

                while (rdtscp() - tsc < extra_waiting_time) {
                }
            }
        }

        sync_ctx_set_action(SYNC_CTX_PAUSE);
        pthread_barrier_wait(sync_ctx.barrier);

        cpython_save_gt("gt.out");

        pthread_barrier_wait(sync_ctx.barrier);
    } while (sync_ctx_get_action() != SYNC_CTX_EXIT);

    Py_XDECREF(probe);
    Py_XDECREF(test);
    Py_DECREF(module);

    cpython_free();
}
