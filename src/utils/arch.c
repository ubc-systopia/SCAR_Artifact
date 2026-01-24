#include "arch.h"

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"

const int pinned_cpu0 = 11;
const int pinned_cpu1 = 13;
const int pinned_cpu2 = 15;

/**
 * \description:
 *  set a thread's CPU affinity
 *
 *  \param:
 *         cpu_id:[int]: the core id
 *  \return:
 *         ret:[int]: errno
 */
static int pin_cpu(int cpu_id) {
    cpu_set_t cset;
    CPU_ZERO(&cset);
    CPU_SET(cpu_id, &cset);

    // If pid is zero, then the calling thread is used.
    int ret = sched_setaffinity(0, sizeof(cpu_set_t), &cset);
    if (!ret) {
        int id = sched_getcpu();
        log_info("Pin thread %d to core %d", gettid(), id);
    } else {
        log_warn("Cannot pin core: %d, errno: %d", cpu_id, ret);
    }
    return ret;
}

int iso_cpu() {
    char command[128];
    char output[512] = "", line[128];
    int pid = gettid();
    char* command_fmt = "sudo cset shield --shield --pid %d --threads";
    sprintf(command, command_fmt, pid);

    log_info("Isolate thread: %d using cset", pid);
    FILE* pipe = popen(command, "r");
    if (!pipe) {
        log_error("cannot execute cset shield");
        return 1;
    }
    while (fgets(line, sizeof(line), pipe) != NULL) {
        sprintf(output + strlen(output), "%s", line);
    }
    int ex_code = pclose(pipe);
    log_debug("cset shield pid %d status: %i", pid, WEXITSTATUS(ex_code));
    log_debug(output);
    if (ex_code != 0) {
        log_error("cset shield failed");
        exit(1);
    }
    return ex_code;
}

int iso_pin_cpu(int cpu_id) {
    static int isol_once = 1;
    int ret = 0;
    if (isol_once) {
        --isol_once;
        if ((ret = iso_cpu())) {
            return ret;
        }
    }
    ret = pin_cpu(cpu_id);
    return ret;
}


void wrmsr_on_cpu(uint32_t reg, int cpu, const char* regvals) {
    uint64_t data;
    int fd;
    char msr_file_name[64];

    sprintf(msr_file_name, "/dev/cpu/%d/msr", cpu);
    fd = open(msr_file_name, O_WRONLY);
    if (fd < 0) {
        if (errno == ENXIO) {
            log_error("wrmsr: No CPU %d", cpu);
        } else if (errno == EIO) {
            log_error("wrmsr: CPU %d doesn't support MSRs", cpu);
        } else {
            log_error("wrmsr: open");
        }
    }

    data = strtoull(regvals, NULL, 0);
    log_trace("wrmsr data %lx", data);
    if (pwrite(fd, &data, sizeof data, reg) != sizeof data) {
        if (errno == EIO) {
            log_error(
                "wrmsr: CPU %d cannot set MSR "
                "0x%08x to 0x%016lx",
                cpu, reg, data);
        } else {
            log_error("wrmsr: pwrite");
        }
    }

    close(fd);
}