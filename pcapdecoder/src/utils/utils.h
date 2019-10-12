#ifndef __UTILS_H__
#define __UTILS_H__

typedef signed char        INT8;
typedef short              INT16;
typedef int                INT32;
typedef long long          INT64;
typedef unsigned char      UINT8;
typedef unsigned short     UINT16;
typedef unsigned int       UINT32;
typedef unsigned long long UINT64;

#define ENDIAN_UNKNOWN	0
#define ENDIAN_BIG	    1
#define ENDIAN_LITTLE	2

#define NETWORK_ORDER   1

#define FILE_HEAD_PRE_READ 4

int get_sys_endianness(void);

void create_time_str(UINT32 sec, UINT32 micro_sec);

char* get_time_str();

UINT16 get_int16(unsigned char* buf, int swap);
UINT32 get_int24(unsigned char* buf, int swap);
UINT32 get_int32(unsigned char* buf, int swap);
UINT64 get_int64(unsigned char* buf, int swap);

unsigned char* get_buffer(int size);

UINT32 integer_pow(UINT32 x, UINT32 n);

void dump_hex(unsigned char* buf, int len);
unsigned char* get_memory(int len);
int format_json(unsigned char* o, int ol, unsigned char* d, int dl);


#endif // __UTILS_H__
