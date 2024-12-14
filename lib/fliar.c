#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 500

#include <stdbool.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <pcre.h>

// Define bitmask flags for operation types using 64-bit values
typedef enum {
    LDFL_OP_NONE     = 0ULL,      // No operation
    LDFL_OP_MAP      = 1ULL << 0, // Map operation
    LDFL_OP_EXEC_MAP = 1ULL << 1, // Executable map
    LDFL_OP_MEM_OPEN = 1ULL << 2, // Memory open
    LDFL_OP_STATIC   = 1ULL << 3, // Static file
    LDFL_OP_PERM     = 1ULL << 4, // Change permissions/ownership
    LDFL_OP_DENY     = 1ULL << 5, // Deny access
    LDFL_OP_END      = 0ULL       // End marker (no operation)
} ldfl_operation_t;

// Structure for a single mapping entry
typedef struct {
    const char      *name;           // Name of the mapping rule
    const char      *search_pattern; // Regex or pattern for the match
    ldfl_operation_t operation;      // Operation type (64-bit bitmask)
    const void      *target;         // Target resource (e.g., file path or blob pointer)
    const char      *extra_options;  // Additional options as a string
} ldfl_mapping_t;

// Variadic logger function type
typedef void (*ldfl_logger_t)(int priority, const char *fmt, ...);

// Structure for settings
typedef struct {
    int           log_level; // Log level (e.g., "debug", "info")
    ldfl_logger_t logger;    // Variadic logger function pointer
} ldfl_setting_t;

// Example default blob data
static const unsigned char ldf_default_blob[] = "hello from ld-fliar";

extern const ldfl_setting_t ldfl_setting;

// Default logger implementation (to stderr)
void ldfl_stderr_logger(int priority, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    if (priority > ldfl_setting.log_level)
        return;

    fprintf(stderr, "LOG_%s: ",
            (priority == LOG_EMERG)     ? "EMER"
            : (priority == LOG_ALERT)   ? "ALERT"
            : (priority == LOG_CRIT)    ? "CRIT"
            : (priority == LOG_ERR)     ? "ERR"
            : (priority == LOG_WARNING) ? "WARNING"
            : (priority == LOG_NOTICE)  ? "NOTICE"
            : (priority == LOG_INFO)    ? "INFO"
                                        : "DEBUG");
    vfprintf(stderr, fmt, args);
    va_end(args);
}

void ldfl_syslog_logger(int priority, const char *fmt, ...) {
    if (priority > ldfl_setting.log_level)
        return;

    // build the out log message
    FILE  *stream;
    char  *out;
    size_t len;
    stream = open_memstream(&out, &len);
    va_list args;
    va_start(args, fmt);
    vfprintf(stream, fmt, args);
    va_end(args);
    fflush(stream);
    fclose(stream);
    syslog(priority, "%s", out);
    free(out);
}

// TODO remove
#define FLIAR_STATIC_CONFIG

#ifdef FLIAR_STATIC_CONFIG
// TODO fix path
#include "../cfg/ldfl-config.h"
#endif
