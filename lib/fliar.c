#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcre.h>

// Enum to represent the type of mapping
typedef enum { MAPPING_TYPE_REGEX, MAPPING_TYPE_MEM_OPEN, MAPPING_TYPE_STATIC, MAPPING_TYPE_DENY } mapping_type_t;

// Struct for a single mapping
typedef struct {
    const char *name;            // Name of the mapping
    const char *search_pattern;  // Search pattern
    mapping_type_t type;         // Type of mapping
    const char *replace_pattern; // Replace pattern (optional, used in regex type)
    const char *target;          // Target (optional, used in static type)
} mapping_t;

// Struct for settings
typedef struct {
    const char *log_level; // Log level
    bool cache_first;      // Cache first setting
} settings_t;

#ifdef FLIAR_STATIC_CONFIG
#include "config-fliar.h"
#endif

#define HASHMAP_SIZE 1024

// Structure for a hashmap entry
typedef struct entry {
    char *key;
    void *value;
    struct entry *next;
} entry;

// Hashmap structure
typedef struct hashmap {
    entry *buckets[HASHMAP_SIZE];
} hashmap;

// Hash function for string keys
unsigned int hash(const char *key) {
    unsigned int hash = 0;
    while (*key) {
        hash = (hash * 31) + *key++;
    }
    return hash % HASHMAP_SIZE;
}

// Create a new hashmap
hashmap *create_hashmap() {
    hashmap *map = malloc(sizeof(hashmap));
    if (!map) {
        return NULL;
    }
    for (int i = 0; i < HASHMAP_SIZE; i++) {
        map->buckets[i] = NULL;
    }
    return map;
}

// Insert a key-value pair into the hashmap
void hashmap_insert(hashmap *map, const char *key, void *value) {
    unsigned int index = hash(key);
    entry *entr = map->buckets[index];

    // Check if the key already exists
    while (entr) {
        if (strcmp(entr->key, key) == 0) {
            entr->value = value; // Update value
            return;
        }
        entr = entr->next;
    }

    // Key not found; create a new entry
    entr = malloc(sizeof(entry));
    if (!entr) {
        return;
    }
    strcpy(entr->key, key);
    entr->value = value;
    entr->next = map->buckets[index];
    map->buckets[index] = entr;
}

// Retrieve a value by key from the hashmap
void *hashmap_get(hashmap *map, const char *key) {
    unsigned int index = hash(key);
    entry *entr = map->buckets[index];

    while (entr) {
        if (strcmp(entr->key, key) == 0) {
            return entr->value;
        }
        entr = entr->next;
    }
    return NULL; // Key not found
}

// Remove a key-value pair from the hashmap
void hashmap_remove(hashmap *map, const char *key) {
    unsigned int index = hash(key);
    entry *entr = map->buckets[index];
    entry *prev = NULL;

    while (entr) {
        if (strcmp(entr->key, key) == 0) {
            if (prev) {
                prev->next = entr->next;
            } else {
                map->buckets[index] = entr->next;
            }
            free(entr->key);
            free(entr);
            return;
        }
        prev = entr;
        entr = entr->next;
    }
}

// Free the entire hashmap
void free_hashmap(hashmap *map) {
    for (int i = 0; i < HASHMAP_SIZE; i++) {
        entry *entr = map->buckets[i];
        while (entr) {
            entry *temp = entr;
            entr = entr->next;
            free(temp->key);
            free(temp);
        }
    }
    free(map);
}
