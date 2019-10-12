#ifndef __LOG_H__
#define __LOG_H__

#define TRACE_LOG       0x01
#define TRACE_INFO      0x02
#define TRACE_DEBUG     0x04
#define TRACE_DETAIL    0x08


#define LOG \
    if (trace_level & TRACE_LOG) trace

#define INFO \
    if (trace_level & TRACE_INFO) trace

#define DEBUG \
    if (trace_level & TRACE_DEBUG) trace

#define DETAIL \
    if (trace_level & TRACE_DETAIL) trace

#define ERR err

void trace(const char* format_str, ...);
void err(const char* format_str, ...);

#endif  // __LOG_H__
