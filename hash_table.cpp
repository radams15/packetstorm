//
// Created by rhys on 23/07/24.
//

#include "hash_table.h"

#include <map>
#include <vector>
#include <algorithm>
#include <cstdint>

extern "C" void* hash_table_init() {
    return new std::map<uint32_t, uint32_t>;
}

extern "C" void hash_table_deinit(void* ptr) {
    auto* table = static_cast<std::map<uint32_t, uint32_t> *>(ptr);
    delete table;
}

extern "C" void hash_table_add(void* ptr, uint32_t k, uint32_t v) {
    auto* table = static_cast<std::map<uint32_t, uint32_t> *>(ptr);
    table->insert(std::make_pair(k, v));
    (*table)[k] = v;
}

extern "C" uint32_t hash_table_get(void* ptr, uint32_t k) {
    auto* table = static_cast<std::map<uint32_t, uint32_t> *>(ptr);
    return (*table)[k];
}

extern "C" void hash_table_inc(void* ptr, uint32_t k) {
    auto* table = static_cast<std::map<uint32_t, uint32_t> *>(ptr);

    (*table)[k]++;
}


bool sort_ascending(
    std::pair<uint32_t, uint32_t>& a,
    std::pair<uint32_t, uint32_t>& b
    ) {
    return a.second < b.second;
}

extern "C" void hash_table_iter(void* ptr, hash_table_iter_t callback) {
    auto* table = static_cast<std::map<uint32_t, uint32_t> *>(ptr);

    std::vector<std::pair<uint32_t, uint32_t> > vec(table->begin(), table->end());

    std::sort(vec.begin(), vec.end(), sort_ascending);

    for(auto it=vec.begin() ; it != vec.end() ; it++)
        callback(it->first, it->second);
}

extern "C" uint32_t hash_table_count(void* ptr) {
    auto* table = static_cast<std::map<uint32_t, uint32_t> *>(ptr);
    return table->size();
}
