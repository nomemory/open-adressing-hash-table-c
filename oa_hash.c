#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>

#include "oa_hash.h"

enum oa_ret_ops { DELETE, PUT, GET };

static size_t oa_hash_getidx(oa_hash *htable, size_t idx, uint32_t hash_val, const void *key, enum oa_ret_ops op);
static inline void oa_hash_lp_idx(oa_hash *htable, size_t *idx);
inline static void oa_hash_grow(oa_hash *htable);
static inline bool oa_hash_should_grow(oa_hash *htable);
static inline bool oa_hash_is_tombstone(oa_hash *htable, size_t idx);
static inline void oa_hash_put_tombstone(oa_hash *htable, size_t idx);

oa_hash* oa_hash_new(
    oa_key_ops key_ops, 
    oa_val_ops val_ops, 
    void (*probing_fct)(struct oa_hash_s *htable, size_t *from_idx)) 
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
    if (NULL==htable->buckets) {
        fprintf(stderr,"malloc() failed in file %s at line # %d", __FILE__,__LINE__);
        exit(EXIT_FAILURE);  
    }

    for(int i = 0; i < htable->capacity; i++) {
        htable->buckets[i] = NULL;
    }

    return htable;
}

oa_hash* oa_hash_new_lp(oa_key_ops key_ops, oa_val_ops val_ops) {
    return oa_hash_new(key_ops, val_ops, oa_hash_lp_idx);
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

inline static void oa_hash_grow(oa_hash *htable) {
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
        if (NULL!=crt_pair && !oa_hash_is_tombstone(htable, i)) {
            oa_hash_put(htable, crt_pair->key, crt_pair->val);
            htable->key_ops.free(crt_pair->key, htable->key_ops.arg);
            htable->val_ops.free(crt_pair->val, htable->val_ops.arg);
            free(crt_pair);
        }
    }

    free(old_buckets);
}

inline static bool oa_hash_should_grow(oa_hash *htable) {
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
        idx = oa_hash_getidx(htable, idx, hash_val, key, PUT);

        if (NULL==htable->buckets[idx]) {
            htable->buckets[idx] = oa_pair_new(
                hash_val, 
                htable->key_ops.cp(key, htable->key_ops.arg),
                htable->val_ops.cp(val, htable->val_ops.arg)
            );
        } else {
            // Update the existing value
            // Free the old values
            htable->val_ops.free(htable->buckets[idx]->val, htable->val_ops.arg);
            htable->key_ops.free(htable->buckets[idx]->key, htable->key_ops.arg);
            // Update the new values
            htable->buckets[idx]->val = htable->val_ops.cp(val, htable->val_ops.arg);
            htable->buckets[idx]->key = htable->val_ops.cp(key, htable->key_ops.arg);
            htable->buckets[idx]->hash = hash_val;
        }
   }
    htable->size++;
}

inline static bool oa_hash_is_tombstone(oa_hash *htable, size_t idx) {
    if (NULL==htable->buckets[idx]) {
        return false;
    }
    if (NULL==htable->buckets[idx]->key && 
        NULL==htable->buckets[idx]->val && 
        0 == htable->buckets[idx]->key) {
            return true;
    }        
    return false;
}

inline static void oa_hash_put_tombstone(oa_hash *htable, size_t idx) {
    if (NULL != htable->buckets[idx]) {
        htable->buckets[idx]->hash = 0;
        htable->buckets[idx]->key = NULL;
        htable->buckets[idx]->val = NULL;
    }
}

void *oa_hash_get(oa_hash *htable, const void *key) {
    uint32_t hash_val = htable->key_ops.hash(key, htable->key_ops.arg);
    size_t idx = hash_val % htable->capacity;

    if (NULL==htable->buckets[idx]) {
        return NULL;
    }

    idx = oa_hash_getidx(htable, idx, hash_val, key, GET);

    return (NULL==htable->buckets[idx]) ?
         NULL : htable->buckets[idx]->val;
}

void oa_hash_delete(oa_hash *htable, const void *key) {
    uint32_t hash_val = htable->key_ops.hash(key, htable->key_ops.arg);
    size_t idx = hash_val % htable->capacity;
    
    if (NULL==htable->buckets[idx]) {
        return;
    }

    idx = oa_hash_getidx(htable, idx, hash_val, key, DELETE);
    if (NULL==htable->buckets[idx]) {
        return;
    }

    htable->val_ops.free(htable->buckets[idx]->val, htable->val_ops.arg);
    htable->key_ops.free(htable->buckets[idx]->key, htable->key_ops.arg);

    oa_hash_put_tombstone(htable, idx);
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
            if (oa_hash_is_tombstone(htable, i)) {
                printf("\t\t TOMBSTONE");
            } else {
                printf("\t\thash=%" PRIu32 ", key=", pair->hash);
                print_key(pair->key);
                printf(", value=");
                print_val(pair->val);
            }
        }
        printf("\n");
    }
}
static size_t oa_hash_getidx(oa_hash *htable, size_t idx, uint32_t hash_val, const void *key, enum oa_ret_ops op) {
    do {
        if (op==PUT && oa_hash_is_tombstone(htable, idx)) {
            break;
        }
        if (htable->buckets[idx]->hash == hash_val && 
            htable->key_ops.eq(key, htable->buckets[idx]->key, htable->key_ops.arg)) {
            break;
        }
        htable->probing_fct(htable, &idx);
    } while(NULL!=htable->buckets[idx]);
    return idx;
}

// Probing functions

static inline void oa_hash_lp_idx(oa_hash *htable, size_t *idx) {
    (*idx)++;
    if ((*idx)==htable->capacity) {
        (*idx) = 0;
    }
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

#define WRITES 10
#define READS 10

int main(int argc, char *argv[]) {
    oa_hash *h = oa_hash_new(oa_key_ops_string, oa_val_ops_string, oa_hash_lp_idx);

    oa_hash_put(h, "Bucharest", "Romania");
    oa_hash_put(h, "Sofia", "Bulgaria");

    printf("%s\n", oa_hash_get(h, "Bucharest"));
    printf("%s\n", oa_hash_get(h, "Sofia"));

    return 0;
}   