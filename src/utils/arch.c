#include "arch.h"

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"

const int pinned_cpu0 = 10;
const int pinned_cpu1 = 12;
const int pinned_cpu2 = 14;

/**
 * \description:
 *  set a thread's CPU affinity
 *
 *  \param:
 *         cpu_id:[int]: the core id
 *  \return:
 *         ret:[int]: errno
 */
int pin_cpu(int cpu_id) {
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
