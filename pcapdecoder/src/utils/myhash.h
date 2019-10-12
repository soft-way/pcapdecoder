
#ifndef __MY_HASH_H__
#define __MY_HASH_H__

#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <string.h>


struct entry_s {
    char* key[128];
    char* value;
    int size;
    struct entry_s* next;
};

typedef struct entry_s entry_t;

struct hashtable_s {
    int size;
    struct entry_s** table;
};

typedef struct hashtable_s hashtable_t;


hashtable_t* ht_create(int size);
int ht_set(hashtable_t* hashtable, char* key, char* value, int size);
unsigned char* ht_get(hashtable_t* hashtable, char* key, int* size);
int ht_del(hashtable_t* hashtable, char* key);

#endif //  __MY_HASH_H__