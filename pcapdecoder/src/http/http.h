#ifndef __HTTP_H__
#define __HTTP_H__

#define HTTP_HEADER_NUM 100

typedef struct {
    unsigned char* name_start;
    int name_size;
    unsigned char* value_start;
    int value_size;
} HTTP_HEADER_FIELD;

int parseHTTP(unsigned char* data, int len);
void get_http_first_header(unsigned char* p, unsigned char* t);

int out_http_header(HTTP_HEADER_FIELD* h, int s);
int out_http_content(unsigned char* p, int l);

void get_extension(unsigned char* p);

#endif // __HTTP_H__
