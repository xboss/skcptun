#include "sslog.h"

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <sys/time.h>
#endif
#include <time.h>

#define _OK 0
#define _ERR -1

struct sslog_s {
    FILE *fp;
    sslog_level log_level;
    /* char *logfile; */
    /* char fmt[64]; */
};
typedef struct sslog_s sslog_t;

static char *level_desc[] = {"DEBUG", "INFO", "NOTICE", "WARN", "ERROR", "FATAL"};
static sslog_t *g_log = NULL;

int sslog_init(char *file, sslog_level log_level) {
    g_log = (sslog_t *)calloc(1, sizeof(sslog_t));
    if (!g_log) {
        fprintf(stderr, "alloc sslog_t failed\n");
        return _ERR;
    }
    FILE *fp = stdout;
    if (file && strlen(file) > 0 && (fp = fopen(file, "a")) == NULL) {
        fprintf(stderr, "can't open log file %s\n", file);
    }
    g_log->fp = fp;
    g_log->log_level = log_level;
    return _OK;
}

void sslog_free() {
    if (!g_log) return;
    if (g_log->fp) {
        fclose(g_log->fp);
        g_log->fp = NULL;
    }
    free(g_log);
    g_log = NULL;
}

void sslog(sslog_level level, const char *fmt, ...) {
    if (!g_log) {
        fprintf(stderr, "sslog error log.\n");
        return;
    }
    if (level < g_log->log_level) return;
#ifdef _WIN32
    fprintf(g_log->fp, "%s ", level_desc[level]);
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    time_t t = time(NULL);
    struct tm *time = localtime(&t);
    char buf[64];
    memset(buf, 0, sizeof(buf));
    size_t written = strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", time);
    if (written == 0) {
        fprintf(stderr, "strftime failed\n");
        return;
    }
    fprintf(g_log->fp, "%s.%ld %s ", buf, tv.tv_usec / 1000l, level_desc[level]);
#endif

    va_list ap;
    va_start(ap, fmt);
    vfprintf(g_log->fp, fmt, ap);
    va_end(ap);
    fprintf(g_log->fp, "\n");
    fflush(g_log->fp);
}
