#include "cpython_runtime.h"

#include "arch.h"
#include "config.h"
#include "fs.h"
#include "log.h"
#include "Python.h"
#include "shared_memory.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PATH_LEN (256)

sync_ctx_t sync_ctx;

static char s_initial_key_path[PATH_LEN] = "";

void cpython_pow_set_key(const char *path) {
	strncpy(s_initial_key_path, path, PATH_LEN - 1);
	s_initial_key_path[PATH_LEN - 1] = '\0';
}

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

	if (s_initial_key_path[0] != '\0') {
		char cmd[PATH_LEN + 16];
		snprintf(cmd, sizeof(cmd), "key_path = '%s'", s_initial_key_path);
		PyRun_SimpleString(cmd);
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
	uint32_t extra_waiting_time = 40000;

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
	PyObject *set_key = PyObject_GetAttrString(module, "set_key");
	if (!set_key)
		PyErr_Clear();

	// Signal init done
	log_info("Sync context init barrier %lu", rdtscp());
	pthread_barrier_wait(sync_ctx.barrier);
	log_info("Sync context init done %lu", rdtscp());

	// Wait for attacker process
	log_info("Runtime wait attacker initialization barrier %lu", rdtscp());
	pthread_barrier_wait(sync_ctx.barrier);
	log_info("Runtime wait Attacker initialization done %lu", rdtscp());

	uint64_t *data = calloc(PAGE_SIZE, sizeof(uint64_t));
	int iteration = 0;
	create_directory("output/cpython_gt");

	do {
		log_info("Runtime start barrier %lu", rdtscp());
		pthread_barrier_wait(sync_ctx.barrier);
		log_info("Runtime start done %lu", rdtscp());

		sync_ctx_action_t action = sync_ctx_get_action();
		if (action == SYNC_CTX_EXIT) {
			break;
		}

		python_opcode_log_ctr = 0;
		uint64_t tsc = rdtscp();
		/* log_info("Runtime start %lu", rdtscp()); */

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
		} else if (action == SYNC_CTX_PROBE) {
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
		} else if (action == SYNC_CTX_SET_KEY) {
			char *key_path = (char *)sync_ctx.data;
			log_info("Reloading key: %s", key_path);
			assert(set_key != NULL);
			PyObject *arg = PyUnicode_FromString(key_path);
			PyObject *ret = PyObject_CallOneArg(set_key, arg);
			Py_XDECREF(ret);
			Py_DECREF(arg);
		} else {
			// FIXME
			log_error("Unexpected action %s (%d)",
			          sync_ctx_action_name(action),
			          action);
		}

		sync_ctx_set_action(SYNC_CTX_PAUSE);
		log_info("Runtime end barrier %lu", rdtscp());
		pthread_barrier_wait(sync_ctx.barrier);
		log_info("Runtime end done %lu", rdtscp());

		char filename[256];
		snprintf(filename, 256, "output/cpython_gt/gt_%d.out", iteration++);
		cpython_save_gt(filename);

	} while (1);

	Py_XDECREF(set_key);
	Py_XDECREF(probe);
	Py_XDECREF(test);
	Py_DECREF(module);

	cpython_free();
}
