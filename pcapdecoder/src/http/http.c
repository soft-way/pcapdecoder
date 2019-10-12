
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <errno.h>

#include "log.h"
#include "utils.h"
#include "http.h"

#include "tcpip.h"

extern UINT32 trace_level;
extern unsigned char time_str[128];
extern UINT32 eth_num;

char first_header[256] = { 0 };
char content_type[128] = { 0 };
int http_num = 0;

int parseHTTP(unsigned char* data, int len) {
    INFO("PDU is HTTP\n");

    HTTP_HEADER_FIELD http_header[HTTP_HEADER_NUM];
    memset(http_header, 0, sizeof(http_header));

    int return_len = 0;
    unsigned char* content_start = 0;
    int content_len = 0;
    unsigned char* p = data;
    int idx = 0;
    while (*p && (p - data < len)) {
        if (idx >= sizeof(http_header)) {
            ERR("Header size buff is not enough, expected: %d, real: %d", idx+1, sizeof(http_header));
            exit(15);
        }

        unsigned char* q = p;
        while (*q != ':')
            q++;
        http_header[idx].name_start = p;
        http_header[idx].name_size = q - p;

        q += 2;
        p = q;
        while (*q != '\r') q++;
        http_header[idx].value_start = p;
        http_header[idx].value_size = q - p;

        if (memcmp(http_header[idx].name_start, "Content-Length", 14) == 0) {
            unsigned char* r = http_header[idx].value_start;
            while (*r != '\r') content_len = content_len * 10 + *r++ - '0';
        } else if (memcmp(http_header[idx].name_start, "Content-Type", 12) == 0) {
            unsigned char* r = http_header[idx].value_start;
            while (*r != '\r') r++;
            memcpy(content_type, http_header[idx].value_start, r- http_header[idx].value_start);
            content_type[r - http_header[idx].value_start] = 0;
        }
        idx++;

        p = q + 2;
        if (*p == '\r') { // end of header
            content_start = p + 2;
            break;
        }
    }

    if (content_len == 0) {
        http_num++;
        out_http_header(http_header, idx);
        return_len = content_start - data - 2;
    } else if ((len - (content_start - data)) < content_len) {
        INFO("Part of PDU data in next tcp package\n");

        unsigned char* ptr = get_memory(len);
        memcpy(ptr, data, len);
        add_tcp_data(ptr, len);

        return_len = 0;
    } else {
        http_num++;
        out_http_header(http_header, idx);
        out_http_content(content_start, len-(content_start-data));

        return_len = len;
    }

    return return_len;
}

int out_http_header(HTTP_HEADER_FIELD* h, int s) {
    char filename[512];
    int out_l = 0;

    get_http_first_header(h[0].name_start, first_header);

    sprintf(filename, "%s___%s_%05d-%s_%05d___HTTP%04d-ETH%04d___%s__0_header.txt",
            time_str, src_ip, src_port, dest_ip, dest_port, http_num, eth_num, first_header);
    FILE* out = fopen(filename, "wb");
    if (out == NULL) {
        ERR("Could not open file %s, err(%d): %s\n", filename, errno, strerror(errno));
        exit(17);
    }
    DEBUG("Writing to file: %s\n", filename);

    int i = 0;
    for (i = 0; i < s; i++) {
        out_l = fwrite(h[i].name_start, 1, h[i].name_size+ h[i].value_size+2, out);
        out_l += fwrite("\r\n", 1, 2, out);
    }

    fclose(out);

    return out_l;

}

void get_extension(unsigned char* p) {
    if (strstr(content_type, "json") != 0) {
        strcpy(p, "json");
    } else {
        strcpy(p, "dat");
    }
}

int out_http_content(unsigned char* p, int len) {
    char filename[512];
    char ext[16];

    get_extension(ext);

    sprintf(filename, "%s___%s_%05d-%s_%05d___HTTP%04d-ETH%04d___%s__1_content.%s",
            time_str, src_ip, src_port, dest_ip, dest_port, http_num, eth_num, first_header, ext);
    FILE* out = fopen(filename, "wb");
    if (out == NULL) {
        ERR("Could not open file %s, err(%d): %s\n", filename, errno, strerror(errno));
        exit(18);
    }
    DEBUG("Writing file: %s\n", filename);
    int out_len = fwrite(p, 1, len, out);
    fclose(out);

    if (memcmp(ext, "json", 4) == 0) {
        strcat(filename, ".txt");
        out = fopen(filename, "wb");
        if (out == NULL) {
            ERR("Could not open file %s, err(%d): %s\n", filename, errno, strerror(errno));
            exit(18);
        }

        int buf_len = 5 * len; // we hope 5 times original string len is enough
        unsigned char* n = get_memory(buf_len);
        int n_len = format_json(p, len, n, buf_len);

        out_len = fwrite(n, 1, n_len, out);

        fclose(out);
        free(n);
    }

    return out_len;
}

void get_http_first_header(unsigned char* p, unsigned char* t) {
    unsigned char* s = t;
    int max_header_len = 100;
    while (*p && *p != '\r' && *p != '\0') {
        switch (*p) {
        case ' ':
            *s++ = '_';
            break;

        case '/':
        case '?':
        case '=':
        case '&':
        case '%':
            *s++ = '#';
            break;

        default:
            *s++ = *p;
        }

        p++;
    }
    *s = '\0';
    if (s - t > max_header_len) {
        t[max_header_len] = 0;
    }
}
