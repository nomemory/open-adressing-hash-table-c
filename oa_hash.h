#include <stddef.h>
#include <inttypes.h>
#include <stdbool.h>

#define OA_HASH_LOAD_FACTOR (0.75)
#define OA_HASH_GROWTH_FACTOR (1<<2)
#define OA_HASH_INIT_CAPACITY (1<<4)

typedef struct oa_key_ops_s {
    uint32_t (*hash)(const void *data, void *arg);
    void* (*cp)(const void *data, void *arg);
    void (*free)(void *data, void *arg);
    bool (*eq)(const void *data1, const void *data2, void *arg);
    void *arg;
} oa_key_ops;

typedef struct oa_val_ops_s {
    void* (*cp)(const void *data, void *arg);
    void (*free)(void *data, void *arg);
    bool (*eq)(const void *data1, const void *data2, void *arg);
    void *arg;
} oa_val_ops;

typedef struct oa_pair_s {
    uint32_t hash;
    void *key;
    void *val;
} oa_pair;

typedef struct oa_hash_s {
    size_t capacity;
    size_t size;
    oa_pair **buckets;
    void (*probing_fct)(struct oa_hash_s *htable, size_t *from_idx);
    oa_key_ops key_ops;
    oa_val_ops val_ops;
} oa_hash;


oa_hash* oa_hash_new(oa_key_ops key_ops, oa_val_ops val_ops, void (*probing_fct)(struct oa_hash_s *htable, size_t *from_idx));
oa_hash* oa_hash_new_lp(oa_key_ops key_ops, oa_val_ops val_ops);
void oa_hash_free(oa_hash *htable);
void oa_hash_put(oa_hash *htable, const void *key, const void *val);
void *oa_hash_get(oa_hash *htable, const void *key);
void oa_hash_delete(oa_hash *htable, const void *key);
void oa_hash_print(oa_hash *htable, void (*print_key)(const void *k), void (*print_val)(const void *v));

// Pair related
oa_pair *oa_pair_new(uint32_t hash, const void *key, const void *val);

// String operations
uint32_t oa_string_hash(const void *data, void *arg);
void* oa_string_cp(const void *data, void *arg);
bool oa_string_eq(const void *data1, const void *data2, void *arg);
void oa_string_free(void *data, void *arg);
void oa_string_print(const void *data);