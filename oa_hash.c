#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>

#include "oa_hash.h"

oa_hash* oa_hash_new(
    oa_key_ops key_ops, 
    oa_val_ops val_ops, 
    size_t (*probing_fct)(struct oa_hash_s *htable, size_t from_idx, uint32_t hash_val, const void *key)) 
{
    oa_hash *htable;
    
    htable = malloc(sizeof(*htable));

    if (NULL==htable) {
        fprintf(stderr,"malloc() failed in file %s at line # %d", __FILE__,__LINE__);
        exit(EXIT_FAILURE);  
    }

    htable->size = 0;
    htable->capacity = OA_HASH_INIT_CAPACITY;
    htable->val_ops = val_ops;
    htable->key_ops = key_ops;
    htable->probing_fct = probing_fct;

    htable->buckets = malloc(sizeof(*(htable->buckets)) * htable->capacity);

    for(int i = 0; i < htable->capacity; i++) {
        htable->buckets[i] = NULL;
    }

    if (NULL==htable->buckets) {
        fprintf(stderr,"malloc() failed in file %s at line # %d", __FILE__,__LINE__);
        exit(EXIT_FAILURE);  
    }

    return htable;
}

void oa_hash_free(oa_hash *htable) {
    for(int i = 0; i < htable->capacity; i++) {
        if (NULL!=htable->buckets[i]) {
            htable->key_ops.free(htable->buckets[i]->key, htable->key_ops.arg);
            htable->val_ops.free(htable->buckets[i]->val, htable->val_ops.arg);
        }
        free(htable->buckets[i]);
    }
    free(htable->buckets);
    free(htable);
}

static void oa_hash_grow(oa_hash *htable) {
    uint32_t old_capacity;
    oa_pair **old_buckets;
    oa_pair *crt_pair;

    uint64_t new_capacity_64 = (uint64_t) htable->capacity * OA_HASH_GROWTH_FACTOR;
    if (new_capacity_64 > SIZE_MAX) {
        fprintf(stderr, "re-size overflow in file %s at line # %d", __FILE__,__LINE__);
        exit(EXIT_FAILURE);
    }

    old_capacity = htable->capacity;
    old_buckets = htable->buckets;

    htable->capacity = (uint32_t) new_capacity_64;
    htable->size = 0;
    htable->buckets = malloc(htable->capacity * sizeof(*(htable->buckets)));

    if (NULL == htable->buckets) {
        fprintf(stderr,"malloc() failed in file %s at line # %d", __FILE__,__LINE__);
        exit(EXIT_FAILURE);  
    }

    for(int i = 0; i < htable->capacity; i++) {
        htable->buckets[i] = NULL;
    };

    for(size_t i = 0; i < old_capacity; i++) {
        crt_pair = old_buckets[i];
        if (NULL!=crt_pair) {
            oa_hash_put(htable, crt_pair->key, crt_pair->val);
            htable->key_ops.free(crt_pair->key, htable->key_ops.arg);
            htable->val_ops.free(crt_pair->val, htable->val_ops.arg);
            free(crt_pair);
        }
    }

    free(old_buckets);
}

static bool oa_hash_should_grow(oa_hash *htable) {
    return (htable->size / htable->capacity) > OA_HASH_LOAD_FACTOR;
}

void oa_hash_put(oa_hash *htable, const void *key, const void *val) {

    if (oa_hash_should_grow(htable)) {
        oa_hash_grow(htable);
    }

    uint32_t hash_val = htable->key_ops.hash(key, htable->key_ops.arg);
    size_t idx = hash_val % htable->capacity;

    if (NULL==htable->buckets[idx]) {
        // Key doesn't exist & we add it anew
        htable->buckets[idx] = oa_pair_new(
                hash_val, 
                htable->key_ops.cp(key, htable->key_ops.arg),
                htable->val_ops.cp(val, htable->val_ops.arg)
        );
    } else {
        // // Probing for the next good index
        idx = htable->probing_fct(htable, idx, hash_val, key);

        if (NULL==htable->buckets[idx]) {
            htable->buckets[idx] = oa_pair_new(
                hash_val, 
                htable->key_ops.cp(key, htable->key_ops.arg),
                htable->val_ops.cp(val, htable->val_ops.arg)
            );
        } else {
            // Update the existing value
            htable->val_ops.free(htable->buckets[idx]->val, htable->val_ops.arg);
            htable->buckets[idx]->val = htable->val_ops.cp(val, htable->val_ops.arg);
        }
   }
    htable->size++;
}

void *oa_hash_get(oa_hash *htable, const void *key) {
    uint32_t hash_val = htable->key_ops.hash(key, htable->key_ops.arg);
    size_t idx = hash_val % htable->capacity;

    if (NULL==htable->buckets[idx]) {
        return NULL;
    }

    idx = htable->probing_fct(htable, idx, hash_val, key);
    return (NULL==htable->buckets[idx]) ?
         NULL : htable->buckets[idx]->val;
}

void oa_hash_print(oa_hash *htable, void (*print_key)(const void *k), void (*print_val)(const void *v)) {

    oa_pair *pair;

    printf("Hash Capacity: %lu\n", htable->capacity);
    printf("Hash Size: %lu\n", htable->size);

    printf("Hash Buckets:\n");
    for(int i = 0; i < htable->capacity; i++) {
        pair = htable->buckets[i];
        printf("\tbucket[%d]:\n", i);
        if (NULL!=pair) {
            printf("\t\thash=%" PRIu32 ", key=", pair->hash);
            print_key(pair->key);
            printf(", value=");
            print_val(pair->val);
        }
        printf("\n");
    }
}

// Probing functions

// Probing functions
size_t oa_hash_linear_probing(oa_hash *htable, size_t idx, uint32_t hash_val, const void *key) {
    do {
        if (htable->buckets[idx]->hash == hash_val && 
            htable->key_ops.eq(key, htable->buckets[idx]->key, htable->key_ops.arg)) {
            break;
        }
        idx++;
        if (idx==htable->capacity) idx = 0;
    } while(NULL!=htable->buckets[idx]);
    return idx;
}

size_t oa_hash_quadratic_probing(oa_hash *htable, size_t idx, uint32_t hash_val, const void *key) {
    // To be implemented
    return 0;
}

// Pair related

oa_pair *oa_pair_new(uint32_t hash, const void *key, const void *val) {
    oa_pair *p;
    p = malloc(sizeof(*p));
    if (NULL==p) {
        fprintf(stderr,"malloc() failed in file %s at line # %d", __FILE__,__LINE__);
        exit(EXIT_FAILURE);  
    }
    p->hash = hash;
    p->val = (void*) val;
    p->key = (void*) key;
    return p;
}

// String operations

static uint32_t oa_hash_fmix32(uint32_t h) {
    h ^= h >> 16;
    h *= 0x3243f6a9U;
    h ^= h >> 16;
    return h;
}

uint32_t oa_string_hash(const void *data, void *arg) {
    
    //djb2
    uint32_t hash = (const uint32_t) 5381;
    const char *str = (const char*) data;
    char c;
    while((c=*str++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return oa_hash_fmix32(hash);
}


void* oa_string_cp(const void *data, void *arg) {
    const char *input = (const char*) data;
    size_t input_length = strlen(input) + 1;
    char *result;
    result = malloc(sizeof(*result) * input_length);
    if (NULL==result) {
        fprintf(stderr,"malloc() failed in file %s at line # %d", __FILE__,__LINE__);
        exit(EXIT_FAILURE);
    }
    strcpy(result, input);
    return result;
}

bool oa_string_eq(const void *data1, const void *data2, void *arg) {
    const char *str1 = (const char*) data1;
    const char *str2 = (const char*) data2;
    return !(strcmp(str1, str2)) ? true : false;    
}

void oa_string_free(void *data, void *arg) {
    free(data);
}

void oa_string_print(const void *data) {    
    printf("%s", (const char*) data);
}

oa_key_ops oa_key_ops_string = { oa_string_hash, oa_string_cp, oa_string_free, oa_string_eq, NULL};
oa_val_ops oa_val_ops_string = { oa_string_cp, oa_string_free, oa_string_eq, NULL};

#define WRITES 10000000
#define READS 10000000

int main(int argc, char *argv[]) {
    oa_hash *h = oa_hash_new(oa_key_ops_string, oa_val_ops_string, oa_hash_linear_probing);

    for(int i = 0; i < WRITES; i++) {
        char key[16];
        snprintf(key, sizeof(key), "%d", i);
        oa_hash_put(h, key, "AAA");
    }

    for(int i = 0; i < READS; i++) {
        char key[16];
        snprintf(key, sizeof(key), "%d", i);
       // printf("looking for key: %s\n", key);
        if (NULL==oa_hash_get(h, key)) {
            //fprintf(stderr, "\t >> Something went wrong, cannot find key: %s\n", key);
            //exit(EXIT_FAILURE);
        } else {
            //printf("\t >> found\n");
        }
    }

    oa_hash_free(h);

    return 0;
}   