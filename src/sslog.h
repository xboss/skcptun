#ifndef _SSLOG_H
#define _SSLOG_H

typedef enum {
    SSLOG_LEVEL_DEBUG = 0,
    SSLOG_LEVEL_INFO,
    SSLOG_LEVEL_NOTICE,
    SSLOG_LEVEL_WARN,
    SSLOG_LEVEL_ERROR,
    SSLOG_LEVEL_FATAL
} sslog_level;

int sslog_init(char *file, sslog_level level);
void sslog_free();
void sslog(sslog_level level, const char *fmt, ...);

#ifndef _LOG
#define _LOG(fmt, ...) sslog(SSLOG_LEVEL_DEBUG, fmt, ##__VA_ARGS__);
#endif

#ifndef _LOG_W
#define _LOG_W(fmt, ...) sslog(SSLOG_LEVEL_WARN, fmt, ##__VA_ARGS__);
#endif

#ifndef _LOG_E
#define _LOG_E(fmt, ...) sslog(SSLOG_LEVEL_ERROR, fmt, ##__VA_ARGS__);
#endif

#endif /* SSLOG_H */