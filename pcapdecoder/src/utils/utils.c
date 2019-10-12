
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include "utils.h"
#include "log.h"

unsigned char time_str[128];
unsigned char* current_read_buf = 0;
INT32 current_read_buf_size;

extern UINT32 trace_level;

void create_time_str(UINT32 sec, UINT32 micro_sec) {
    unsigned char buf[128];
    time_t time_value = sec;
    strftime(buf, 20, "%Y_%m_%d-%H_%M_%S", localtime(&time_value));

    sprintf(time_str, "%s.%06d", buf, micro_sec);
}

char* get_time_str() {
    return time_str;
}

UINT16 get_int16(unsigned char* buf, int swap) {
    union {
        UINT16 w;
        unsigned char c[sizeof(UINT16)];
    } uw;


    if (swap) {
        int i = 0;
        for (i = 0; i < 2; i++) uw.c[i] = buf[1 - i];
    } else {
        int i = 0;
        for (i = 0; i < 2; i++) uw.c[i] = buf[i];
    }

    return (uw.w);
}

UINT32 get_int24(unsigned char* buf, int swap) {
    if (swap) {
        return (*(buf + 2) << 16 | *(buf + 1) << 8 | *(buf));
    }
    return (*(buf) << 16 | *(buf + 1) << 8 | *(buf + 2));
}

UINT32 get_int32(unsigned char* buf, int swap) {
    union {
        UINT32 s;
        unsigned char c[sizeof(UINT32)];
    } us;


    if (swap) {
        int i = 0;
        for (i = 0; i < 4; i++) us.c[i] = buf[3 - i];
    } else {
        int i = 0;
        for (i = 0; i < 4; i++) us.c[i] = buf[i];
    }

    return (us.s);
}

UINT64 get_int64(unsigned char* buf, int swap) {
    union {
        UINT64 l;
        unsigned char c[sizeof(UINT64)];
    } ul;


    if (swap) {
        int i = 0;
        for (i = 0; i < 8; i++) ul.c[i] = buf[7 - i];
    } else {
        int i = 0;
        for (i = 0; i < 8; i++) ul.c[i] = buf[i];
    }

    return (ul.l);
}

unsigned char* get_buffer(int size) {
    unsigned char* p = 0;
    if (current_read_buf == NULL) {
        p = malloc(size);
    } else if (size > current_read_buf_size) {
        free(current_read_buf);
        p = malloc(size);
    }

    if (p == NULL) {
        ERR("Memory allocation(%d) failure\n", size);
        exit(35);
    }

    return p;
}

UINT32 integer_pow(UINT32 x, UINT32 n) {
    UINT32 r = 1;
    while (n--)
        r *= x;

    return r;
}

void dump_hex(unsigned char* buf, int len) {
    int i = 0;
    if (!(trace_level & TRACE_DETAIL)) {
        return;
    }

    int offset = 0;
    fprintf(stdout, "File offset: %#08x\n", offset);
    fprintf(stdout, "          00 01 02 03 04 05 06 07 - 08 09 0A 0B 0C 0D 0E 0F\n");
    fprintf(stdout, "%#08x: ", i);
    while (i < len) {
        int first_char = buf[i] >> 4;
        if (first_char >= 0 && first_char <= 9) {
            fprintf(stdout, "%d", first_char);
        } else {
            fprintf(stdout, "%c", first_char - 10 + 'A');
        }

        int second_char = buf[i] & 0x0F;
        if (second_char >= 0 && second_char <= 9) {
            fprintf(stdout, "%d", second_char);
        } else {
            fprintf(stdout, "%c", second_char - 10 + 'A');
        }

        i++;
        if (i % 16 == 0) {
            fprintf(stdout, "\n");
            fprintf(stdout, "%#08x: ", i);
        } else if (i % 8 == 0) {
            fprintf(stdout, " - ");
        } else {
            fprintf(stdout, " ");
        }
    }
    fprintf(stdout, "\n");
}

unsigned char* get_memory(int len) {
    unsigned char* p = malloc(len);
    if (p == NULL) {
        ERR("Could not get memory size: %d\n", len);
        exit(16);
    }
    return p;
}

int format_json(unsigned char* o, int ol, unsigned char* d, int dl) {
    int i = 0, j = 0;
    int level = 0;
    int ident = 2;
    while (i < ol && j < dl) {
        if (o[i] == '{' || o[i] == '[') {
            level++;
            d[j++] = o[i];
            d[j++] = '\n';

            int k = 0;
            for (k = 0; k < level * ident; k++) {
                d[j++] = ' ';
            }
        } else if (o[i] == '}' || o[i] == ']') {
            level--;
            d[j++] = '\n';
            int k = 0;
            for (k = 0; k < level * ident; k++) {
                d[j++] = ' ';
            }
            d[j++] = o[i];
        } else if (o[i] == ',') {
            d[j++] = ',';
            d[j++] = '\n';
            int k = 0;
            for (k = 0; k < level * ident; k++) {
                d[j++] = ' ';
            }
            while (o[i + 1] == ' ') i++;
        } else {
            d[j++] = o[i];
        }

        i++;
    }

    return j;
}

int get_sys_endianness(void) {
    union {
        short s;
        char c[sizeof(short)];
    } un;

    un.s = 0x0102;

    if (sizeof(short) == 2) {
        if (un.c[0] == 1 && un.c[1] == 2)
            return ENDIAN_BIG;
        else if (un.c[0] == 2 && un.c[1] == 1)
            return ENDIAN_LITTLE;
        else
            return ENDIAN_UNKNOWN;
    } else {
        return ENDIAN_UNKNOWN;
    }
}
