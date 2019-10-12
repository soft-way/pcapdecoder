
#include <stdio.h>
#include <stdarg.h>

#include "utils.h"

#include "log.h"

UINT32 trace_level = TRACE_LOG;

void trace(const char* format_str, ...) {
    char buf[2048];
    va_list args;
    va_start(args, format_str);
    vsnprintf(buf, sizeof(buf), format_str, args);
    va_end(args);

    fprintf(stdout, "%s", buf);
}

void err(const char* format_str, ...) {
    char buf[2048];
    va_list args;
    va_start(args, format_str);
    vsnprintf(buf, sizeof(buf), format_str, args);
    va_end(args);

    fprintf(stderr, "%s", buf);
}

