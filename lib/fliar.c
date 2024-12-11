#include <stdbool.h>
#include <stddef.h>

// Enum to represent the type of mapping
typedef enum {
    MAPPING_TYPE_REGEX,
    MAPPING_TYPE_MEM_OPEN,
    MAPPING_TYPE_STATIC
} mapping_type_t;

// Struct for a single mapping
typedef struct {
    const char* name;            // Name of the mapping
    const char* search_pattern;  // Search pattern
    mapping_type_t type;         // Type of mapping
    const char* replace_pattern; // Replace pattern (optional, used in regex type)
    const char* target;          // Target (optional, used in static type)
} mapping_t;

// Struct for settings
typedef struct {
    const char* log_level; // Log level
    bool cache_first;      // Cache first setting
} settings_t;

// Struct for overall configuration
typedef struct {
    settings_t settings;    // Settings
    const mapping_t* mappings; // Pointer to mappings array
    size_t mappings_count;  // Number of mappings
} configuration_t;
