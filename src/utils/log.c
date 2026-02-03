#include "log.h"

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysinfo.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static const char *log_level_strings[] = {
    "TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL", "FORCE",
};

static const char *log_colors[] = {
    "\x1B[38;5;246m", "\x1B[94m", "\x1B[32m", "\x1B[33m", "\x1B[31m", "\x1B[38;5;225m", "\x1B[35m"
};

static int log_initialized = 0;
static FILE *log_file;

void get_program_cmdline() {
    char cmdline[1024], cmd[64];
    int pid = getpid();
    FILE *fp;
    log_force("Program command-line:\n");
    sprintf(cmd, "cat /proc/%d/cmdline | sed -e \"s/\\x00/ /g\"; echo", pid);
    fp = popen(cmd, "r");
    while (fgets(cmdline, sizeof(cmdline), fp) != NULL) {
        cmdline[strlen(cmdline) - 1] = '\0';
        log_force_raw(cmdline);
    }
    log_force(SEPARATION_LINE);
}

void get_cpu_frequency() {
    int nprocs = get_nprocs_conf(), get_nprocs();
    const char *freq_temp =
            "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_cur_freq";
    char freq_filepath[128];
    uint64_t freq;
    FILE *fp;

    log_force("Core Frequency:\n");
    for (int i = 0; i < nprocs; ++i) {
        sprintf(freq_filepath, freq_temp, i);
        fp = fopen(freq_filepath, "r");
        if (fscanf(fp, "%lu", &freq) != 1) {
            log_force("Error reading core %2d frequency", i);
        } else {
            log_force("core %2d freq %7lu", i, freq);
        }
        fclose(fp);
    }
    log_force(SEPARATION_LINE);
}

void get_kernel_cmdline() {
    const char *cmdline_filepath = "/proc/cmdline";
    FILE *fp;
    char cmdline[256];
    log_force("Kernel command-line parameters:\n");
    fp = fopen(cmdline_filepath, "r");
    if (fgets(cmdline, sizeof(cmdline), fp) == NULL) {
        log_force("Error reading /proc/cmdline");
    } else {
        cmdline[strlen(cmdline) - 1] = '\0';
        log_force_raw(cmdline);
    }
    fclose(fp);
    log_force(SEPARATION_LINE);
}

void get_git_status() {
    // branch
    FILE *fp;
    char git_branch[32] = "";
    char git_hash[64] = "";
    char buffer[1024] = "";
    log_force("Project Git status:\n");

    fp = popen("git rev-parse --abbrev-ref HEAD", "r");
    if (fgets(git_branch, sizeof(git_branch), fp) == NULL) {
        log_force("Error reading git hash");
    } else {
        git_branch[strlen(git_branch) - 1] = '\0';
    }
    fclose(fp);

    // commit hash
    fp = popen("git rev-parse HEAD", "r");
    if (fgets(git_hash, sizeof(git_hash), fp) == NULL) {
        log_force("Error reading git hash");
    } else {
        git_hash[strlen(git_hash) - 1] = '\0';
    }
    fclose(fp);

    log_force("Git branch [%s] commit: %s", git_branch, git_hash);

    // git status
    fp = popen("git status", "r");
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        buffer[strlen(buffer) - 1] = '\0';
        log_force_raw(buffer);
    }
    fclose(fp);

    // git diff
    fp = popen("git diff", "r");
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        buffer[strlen(buffer) - 1] = '\0';
        log_force_raw(buffer);
    }
    fclose(fp);

    log_force(SEPARATION_LINE);
}

void get_cset_list() {
    FILE *fp;
    char buffer[1024] = "";
    log_force("Cpuset List:\n");
    fp = popen("sudo cset set --list", "r");
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        buffer[strlen(buffer) - 1] = '\0';
        log_force(buffer);
    }
    log_force(SEPARATION_LINE);
}

void log_system_info() {
    get_program_cmdline();
    get_cpu_frequency();
    get_kernel_cmdline();
    // TODO: uncomment
    get_git_status();
    get_cset_list();
}

void log_init() {
    mkdir("log", 0755);
    char log_filename[64];
    time_t t = time(NULL);
    log_filename[strftime(log_filename, sizeof(log_filename),
                          "log/LLCT_%Y-%m-%dT%H:%M:%S.log", localtime(&t))] =
            '\0';
    log_file = fopen(log_filename, "w");
    if (log_file) {
        char *abspath = realpath(log_filename, NULL);
        log_info("log file: %s", abspath);
    } else {
        fprintf(stderr, "cannot creat log filename %s\n", log_filename);
    }
    log_system_info();
}

void log_get_time_info(char *time_info) {
    char time_fmt[32];
    struct timeval tv;
    gettimeofday(&tv, NULL);
    time_t t = tv.tv_sec;

    time_fmt[strftime(time_fmt, sizeof(time_fmt), "%Y-%m-%d %H:%M:%S",
                      localtime(&t))] = '\0';
    sprintf(time_info, "%s.%06ld", time_fmt, tv.tv_usec);
}

void log_raw(int level, const char *file, int line, const char *buffer) {
    char time_info[32];
    va_list args;
    char *filename = strrchr(file, '/') + 1;

    log_get_time_info(time_info);

    fprintf(stdout, "%s %s[%5s] %s:%-3d: %s%s" LOG_COLOR_RESET "\n", time_info,
            log_colors[level], log_level_strings[level], filename, line,
            log_colors[level], buffer);

    if (log_file) {
        fprintf(log_file, "%s [%5s] %s:%-3d: %s\n", time_info,
                log_level_strings[level], file, line, buffer);
    }
}

void log_fmt(int level, const char *file, int line, const char *fmt, ...) {
    if (!log_initialized) {
        log_initialized = 1;
        log_init();
    }

    char time_info[32];
    va_list args;
    char *filename = strrchr(file, '/') + 1;
    char buffer[1024];

    log_get_time_info(time_info);

    va_start(args, fmt);
    vsprintf(buffer, fmt, args);
    va_end(args);

    fprintf(stdout, "%s %s[%5s] %s:%-3d: %s%s" LOG_COLOR_RESET "\n", time_info,
            log_colors[level], log_level_strings[level], filename, line,
            log_colors[level], buffer);
    fflush(stdout);
    if (log_file) {
        fprintf(log_file, "%s [%5s] %s:%-3d: %s\n", time_info,
                log_level_strings[level], file, line, buffer);
    }
}
