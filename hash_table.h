//
// Created by rhys on 23/07/24.
//

#ifndef HASH_TABLE_H
#define HASH_TABLE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*hash_table_iter_t)(uint32_t k, uint32_t v);

void* hash_table_init();
void hash_table_deinit(void* ptr);
void hash_table_add(void* ptr, uint32_t k, uint32_t v);
uint32_t hash_table_get(void* ptr, uint32_t k);
void hash_table_inc(void* ptr, uint32_t k);
uint32_t hash_table_count(void* ptr);
void hash_table_iter(void* ptr, hash_table_iter_t callback);

#ifdef __cplusplus
}
#endif

#endif //HASH_TABLE_H
