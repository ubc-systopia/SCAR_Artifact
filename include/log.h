#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#define LOG_TRACE (0)
#define LOG_DEBUG (1)
#define LOG_INFO (2)
#define LOG_WARN (3)
#define LOG_ERROR (4)
#define LOG_FATAL (5)
#define LOG_FORCE (6)

#define LOG_LEVEL (LOG_INFO)

#define LOG_COLOR_RESET "\x1B[0m"

#define LOG_BOLD_ON "\e[1m"
#define LOG_BOLD_OFF "\e[0m"

#define LOG_VOID(...) \
do {              \
} while (0)

#if (LOG_TRACE >= LOG_LEVEL)
#define log_trace(...) log_fmt(LOG_TRACE, __FILE__, __LINE__, __VA_ARGS__)
#else
#define log_trace(...) LOG_VOID(...)
#endif

#if (LOG_DEBUG >= LOG_LEVEL)
#define log_debug(...) log_fmt(LOG_DEBUG, __FILE__, __LINE__, __VA_ARGS__)
#else
#define log_debug(...) LOG_VOID(...)
#endif

#if (LOG_INFO >= LOG_LEVEL)
#define log_info(...) log_fmt(LOG_INFO, __FILE__, __LINE__, __VA_ARGS__)
#else
#define log_info(...) LOG_VOID(...)
#endif

#if (LOG_WARN >= LOG_LEVEL)
#define log_warn(...) log_fmt(LOG_WARN, __FILE__, __LINE__, __VA_ARGS__)
#else
#define log_warn(...) LOG_VOID(...)
#endif

#if (LOG_ERROR >= LOG_LEVEL)
#define log_error(...) log_fmt(LOG_ERROR, __FILE__, __LINE__, __VA_ARGS__)
#else
#define log_error(...) LOG_VOID(...)
#endif

#if (LOG_FATAL >= LOG_LEVEL)
#define log_fatal(...) log_fmt(LOG_FATAL, __FILE__, __LINE__, __VA_ARGS__)
#else
#define log_fatal(...) LOG_VOID(...)
#endif

#define log_force(...) log_fmt(LOG_FORCE, __FILE__, __LINE__, __VA_ARGS__)
#define log_force_raw(__s) log_raw(LOG_FORCE, __FILE__, __LINE__, __s)

#define SEPARATION_LINE "----------------------------------------------------------------------"


void log_fmt(int level, const char* file, int line, const char* fmt, ...);
void log_raw(int level, const char* file, int line, const char* buffer);

#ifdef __cplusplus
}
#endif
