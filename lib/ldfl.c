/** @cond */
#define _DEFAULT_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#define _BSD_SOURCE
#define _GNU_SOURCE
#define _XOPEN_SOURCE 700

#include <stdbool.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdio.h>

#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <assert.h>
#include <sys/stat.h>
#include <dirent.h>
#include <dirent.h>
#include <sys/time.h>
#include <utime.h>

#include <glob.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include <syslog.h>
#ifndef PCRE2_CODE_UNIT_WIDTH
#define PCRE2_CODE_UNIT_WIDTH 8
#endif
#include <pcre2.h>
/** @endcond */

/**
 * @file
 * @brief Structures of interest in ldfl.c
 */

/**
 * @enum ldfl_path_type_t
 * @brief flag
 *
 * This enumeration defines if we should use the absolute path
 * or the unaltered path in the transformation.
 */
typedef enum {
    LDFL_PATH_ORIG = 0,
    LDFL_PATH_ABS  = 1,
} ldfl_path_type_t;

/**
 * @enum ldfl_log_category_t
 * @brief Bitmask flags for specifying logging categories.
 *
 * This enumeration defines flags used to control the logging behavior
 * of the ldfl. Each flag represents a specific category of operations
 * to be logged, and they can be combined using bitwise OR operations.
 */
typedef enum {
    LDFL_LOG_FN_CALL             = 1ULL << 0, /**< Log LibC function calls. */
    LDFL_LOG_FN_CALL_ERR         = 1ULL << 1, /**< Log LibC function calls errors */
    LDFL_LOG_MAPPING_RULE_SEARCH = 1ULL << 2, /**< Log mapping search operations. */
    LDFL_LOG_MAPPING_RULE_FOUND  = 1ULL << 3, /**< Log mapping found operations. */
    LDFL_LOG_MAPPING_RULE_APPLY  = 1ULL << 4, /**< Log mapping application operations. */
    LDFL_LOG_INIT                = 1ULL << 5, /**< Log initialization and deinitialization operations. */
    LDFL_LOG_ALL                 = ~0ULL      /**< Log all categories. */
} ldfl_log_category_t;

/**
 * @enum ldfl_operation_t
 * @brief enum for the type of operations
 */
typedef enum {
    LDFL_OP_NOOP     = 1ULL << 0, /**< No operation. */
    LDFL_OP_MAP      = 1ULL << 1, /**< Map operation. */
    LDFL_OP_EXEC_MAP = 1ULL << 2, /**< Executable map. */
    LDFL_OP_MEM_OPEN = 1ULL << 3, /**< Memory open. */
    LDFL_OP_STATIC   = 1ULL << 4, /**< Static file operation. */
    LDFL_OP_PERM     = 1ULL << 5, /**< Change permissions/ownership, use extra_option "user|group|0600|0700" */
    LDFL_OP_DENY     = 1ULL << 6, /**< Deny access. */
    LDFL_OP_RO       = 1ULL << 7, /**< Restrict to Read Only access. */
    LDFL_OP_END      = 0ULL       /**< End marker. */
} ldfl_operation_t;

/**
 * @file
 * @brief Defines the structure for a single mapping entry.
 */

/**
 * @struct ldfl_mapping_t
 * @brief Represents a single file mapping entry.
 *
 * This structure defines a mapping rule, including the name, matching pattern,
 * operation type, target resource, and additional options.
 *
 * @note The array of `ldfl_mapping_t` structures should be terminated with an entry
 * where `name` is `NULL` and `operation` is `LDFL_OP_END`. This sentinel entry is used
 * to mark the end of the array.
 *
 */
typedef struct {
    const char      *name;           /**< Name of the mapping rule. Only informational */
    const char      *search_pattern; /**< Matching regex on file/dir path. set to NULL to chain */
    ldfl_operation_t operation;      /**< Operation type. */
    const void      *target;         /**< Replacement regex for the file/dir path. */
    ldfl_path_type_t path_transform; /**< Use the unaltered or absolute path in the matching*/
    const char      *extra_options;  /**< Extra options options. */
} ldfl_mapping_t;

/**
 * @brief Variadic logger function type.
 *
 * This function type is used for logging messages in ldfl.
 * Implement this signature if you want your own logger
 *
 * @param mask Logging category bitmask (see ldfl_log_category_t).
 * @param priority Priority level of the log message.
 * @param fmt Format string for the log message (like sprintf).
 * @param ... Variadic arguments for the format string.
 *
 * @note Default loggers implementing this interface:
 * - `ldfl_dummy_logger`: A no-op logger that discards all messages.
 * - `ldfl_stderr_logger`: Logs messages to standard error (stderr).
 * - `ldfl_syslog_logger`: Logs messages to the system log (syslog).
 */
typedef void (*ldfl_logger_t)(uint64_t mask, int priority, const char *fmt, ...);

/**
 * @struct ldfl_setting_t
 * @brief Represents the general settings.
 *
 */
typedef struct {
    int           log_level; /**< Log level. As define in 'man syslog' (ex: LOG_ERR) */
    ldfl_logger_t logger;    /**< Variadic logger function pointer. */
    uint64_t      log_mask;  /**< Bitmask of log categories enabled. */
} ldfl_setting_t;

/** @cond */

// Covert ldfl_operation_t to equivalent index
static inline int ldfl_op_index(ldfl_operation_t op) {
    return __builtin_ctzll(op); // count trailing zeros
}

const char *ldfl_operation_to_string(ldfl_operation_t op) {
    switch (op) {
    case LDFL_OP_NOOP:
        return "NOOP";
    case LDFL_OP_MAP:
        return "MAP";
    case LDFL_OP_EXEC_MAP:
        return "EXEC_MAP";
    case LDFL_OP_MEM_OPEN:
        return "MEM_OPEN";
    case LDFL_OP_STATIC:
        return "STATIC";
    case LDFL_OP_PERM:
        return "PERM";
    case LDFL_OP_DENY:
        return "DENY";
    case LDFL_OP_RO:
        return "RO";
    case LDFL_OP_END:
        return "END";
    default:
        return "UNKNOWN";
    }
}

const char *ldfl_log_category_to_string(ldfl_log_category_t category) {
    switch (category) {
    case LDFL_LOG_FN_CALL:
        return "FN_CALL";
    case LDFL_LOG_FN_CALL_ERR:
        return "FN_ERR";
    case LDFL_LOG_MAPPING_RULE_SEARCH:
        return "MAPPING_RULE_SEARCH";
    case LDFL_LOG_MAPPING_RULE_FOUND:
        return "MAPPING_RULE_FOUND";
    case LDFL_LOG_MAPPING_RULE_APPLY:
        return "MAPPING_RULE_APPLY";
    case LDFL_LOG_INIT:
        return "INIT";
    default:
        return "UNKNOWN";
    }
}

// Wrapper struct to store compiled regex
typedef struct {
    const ldfl_mapping_t *mapping;        // Pointer to the original mapping
    pcre2_code           *matching_regex; // Compiled matching regex
} compiled_mapping_t;

uint64_t              ldfl_rule_count;
extern ldfl_setting_t ldfl_setting;

// Empty logger
void ldfl_dummy_logger(uint64_t mask, int priority, const char *fmt, ...) {
    return;
}

// log to stderr logger
void ldfl_stderr_logger(uint64_t mask, int priority, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    if (priority > ldfl_setting.log_level)
        return;
    if (!(mask & ldfl_setting.log_mask))
        return;

    fprintf(stderr, "LOG_%s ",
            (priority == LOG_EMERG)     ? "EMER:    "
            : (priority == LOG_ALERT)   ? "ALERT:   "
            : (priority == LOG_CRIT)    ? "CRIT:    "
            : (priority == LOG_ERR)     ? "ERR:     "
            : (priority == LOG_WARNING) ? "WARNING: "
            : (priority == LOG_NOTICE)  ? "NOTICE:  "
            : (priority == LOG_INFO)    ? "INFO:    "
                                        : "DEBUG:   ");
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
}

// Syslog logger function
void ldfl_syslog_logger(uint64_t mask, int priority, const char *fmt, ...) {
    if (priority > ldfl_setting.log_level)
        return;
    if (!(mask & ldfl_setting.log_mask))
        return;

    // Convert the mask into log category string
    const char *category_str = ldfl_log_category_to_string((ldfl_log_category_t)mask);

    // Allocate a buffer to build the log message
    va_list args;
    va_start(args, fmt);

    FILE  *stream;
    char  *log_message;
    size_t len;
    stream = open_memstream(&log_message, &len);
    fprintf(stream, "LDFL_%s: ", category_str);
    vfprintf(stream, fmt, args);
    va_end(args);
    fflush(stream);
    fclose(stream);

    // Open the syslog
    openlog(NULL, LOG_PID, LOG_USER);
    syslog(priority, "%s", log_message); // Log the built message
    closelog();
    free(log_message);
}

// Render Nullable array (for logging things like argv or envp)
char *ldfl_render_nullable_array(char *const list[]) {
    if (!list)
        return strdup("[]");

    size_t      total_size    = 3; // For the opening '[', closing ']', and null terminator
    const char *separator     = ", ";
    size_t      separator_len = strlen(separator);

    // Calculate the total size needed for the rendered string
    for (int i = 0; list[i] != NULL; i++) {
        total_size += strlen(list[i]) + 2; // Account for quotes around each item
        if (list[i + 1] != NULL)
            total_size += separator_len;
    }

    // Allocate memory for the final string
    char *result = malloc(total_size);
    if (!result)
        return NULL; // Memory allocation failed

    // Build the string
    char *ptr = result;
    *ptr++    = '['; // Add the opening bracket

    for (int i = 0; list[i] != NULL; i++) {
        if (i > 0) {
            memcpy(ptr, separator, separator_len);
            ptr += separator_len;
        }
        *ptr++     = '"'; // Add opening quote
        size_t len = strlen(list[i]);
        memcpy(ptr, list[i], len);
        ptr += len;
        *ptr++ = '"'; // Add closing quote
    }

    *ptr++ = ']';  // Add the closing bracket
    *ptr   = '\0'; // Null-terminate the string

    return result;
}

// Global var for compiled regexp
compiled_mapping_t *ldfl_compiled_rules;

// If static configuration
#ifdef LDFL_CONFIG
#include LDFL_CONFIG
#else
// else json/dynamic configuration
#include "ldfl-config-parser.h"
#endif

#define LDFL_MAX_ARGS 8 // Limit to a maximum of 8 arguments for simplicity

// Generic macro for wrapping variadic calls, limited to 8 arguments and only for NULL terminated list of strings
#define ldfl_variadic_str_wrap(target_func, nvarg, ...)                                                                \
    ({                                                                                                                 \
        void   *_arg;                                                                                                  \
        void   *_args[LDFL_MAX_ARGS] = {0};                                                                            \
        int     _arg_count           = 0;                                                                              \
        va_list va_list_name;                                                                                          \
        va_start(va_list_name, nvarg);                                                                                 \
        _arg = va_arg(va_list_name, void *);                                                                           \
                                                                                                                       \
        /* Extract arguments into the array */                                                                         \
        while (_arg != NULL) {                                                                                         \
            _args[_arg_count++] = _arg;                                                                                \
            _arg                = va_arg(va_list_name, void *);                                                        \
        }                                                                                                              \
        va_end(va_list_name);                                                                                          \
                                                                                                                       \
        ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_CRIT, "call '%s', variadic arg count too high: %d (limit: 8)",       \
                            #target_func, _arg_count);                                                                 \
        /* Call the target function based on the argument count */                                                     \
        int _ret;                                                                                                      \
        switch (_arg_count) {                                                                                          \
        case 0:                                                                                                        \
            _ret = target_func(__VA_ARGS__, NULL);                                                                     \
            break;                                                                                                     \
        case 1:                                                                                                        \
            _ret = target_func(__VA_ARGS__, _args[0], NULL);                                                           \
            break;                                                                                                     \
        case 2:                                                                                                        \
            _ret = target_func(__VA_ARGS__, _args[0], _args[1], NULL);                                                 \
            break;                                                                                                     \
        case 3:                                                                                                        \
            _ret = target_func(__VA_ARGS__, _args[0], _args[1], _args[2], NULL);                                       \
            break;                                                                                                     \
        case 4:                                                                                                        \
            _ret = target_func(__VA_ARGS__, _args[0], _args[1], _args[2], _args[3], NULL);                             \
            break;                                                                                                     \
        case 5:                                                                                                        \
            _ret = target_func(__VA_ARGS__, _args[0], _args[1], _args[2], _args[3], _args[4], NULL);                   \
            break;                                                                                                     \
        case 6:                                                                                                        \
            _ret = target_func(__VA_ARGS__, _args[0], _args[1], _args[2], _args[3], _args[4], _args[5], NULL);         \
            break;                                                                                                     \
        case 7:                                                                                                        \
            _ret =                                                                                                     \
                target_func(__VA_ARGS__, _args[0], _args[1], _args[2], _args[3], _args[4], _args[5], _args[6], NULL);  \
            break;                                                                                                     \
        case 8:                                                                                                        \
            _ret = target_func(__VA_ARGS__, _args[0], _args[1], _args[2], _args[3], _args[4], _args[5], _args[6],      \
                               _args[7], NULL);                                                                        \
            break;                                                                                                     \
        default:                                                                                                       \
            ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_CRIT, "call '%s', variadic arg count too high: %d (limit: 8)",   \
                                #target_func, _arg_count);                                                             \
            _ret = -1; /* Too many arguments */                                                                        \
        }                                                                                                              \
        _ret;                                                                                                          \
    })

#define ldfl_variadic_mode_wrap(target_func, ...)                                                                      \
    ({                                                                                                                 \
        int     _ret;                                                                                                  \
        va_list _args;                                                                                                 \
        mode_t  mode = 0;                                                                                              \
        if ((flags & O_CREAT) || (flags & O_TMPFILE)) {                                                                \
            va_start(_args, flags);                                                                                    \
            mode = va_arg(_args, mode_t);                                                                              \
            va_end(_args);                                                                                             \
            _ret = target_func(__VA_ARGS__, mode);                                                                     \
        } else {                                                                                                       \
            _ret = target_func(__VA_ARGS__);                                                                           \
        };                                                                                                             \
        _ret;                                                                                                          \
    })

// Count the number of rules
uint64_t ldfl_get_rule_count() {
    uint64_t i = 0;
    while (ldfl_mapping[i].operation != LDFL_OP_END)
        i++;
    return i;
}

// Regex compilation
void ldfl_regex_init() {
    ldfl_rule_count = ldfl_get_rule_count();

    ldfl_compiled_rules = calloc(sizeof(compiled_mapping_t), ldfl_rule_count);
    for (int i = 0; i < ldfl_rule_count; i++) {
        ldfl_compiled_rules[i].mapping = &ldfl_mapping[i];
        if (ldfl_mapping[i].search_pattern == NULL) {
            continue;
        }
        pcre2_code *re;
        PCRE2_SPTR  pattern_ptr = (PCRE2_SPTR)ldfl_mapping[i].search_pattern;

        // Error handling variables
        int        errornumber;
        PCRE2_SIZE erroroffset;

        // Compile the regular expression
        re = pcre2_compile(pattern_ptr, PCRE2_ZERO_TERMINATED, 0, &errornumber, &erroroffset, NULL);
        if (!re) {
            PCRE2_UCHAR buffer[256];
            pcre2_get_error_message(errornumber, buffer, sizeof(buffer));
            ldfl_setting.logger(LDFL_LOG_INIT, LOG_CRIT, "rule[%s], PCRE2 compilation failed at offset %d: %s\n",
                                ldfl_mapping[i].name, (int)erroroffset, buffer);
            assert(re);
        }

        ldfl_compiled_rules[i].matching_regex = re;
    }
}

// Free compiled regex data
void ldfl_regex_free() {
    for (int i = 0; i < ldfl_rule_count; i++) {
        pcre2_code_free(ldfl_compiled_rules[i].matching_regex);
    }
    ldfl_rule_count = 0;
    free(ldfl_compiled_rules);
}

bool ldfl_find_matching_rules(const char *call, const char *pathname, uint64_t op_mask,
                              compiled_mapping_t ***return_rules, int *num_rules,
                              pcre2_match_data ***return_pcre_match) {
    if (pathname == NULL) {
        return false;
    }

    // max 64 bits tracked
    compiled_mapping_t *latest_rules[64] = {0};
    pcre2_match_data   *latest_match[64] = {0};
    int                 count            = 0;

    for (int i = 0; i < ldfl_rule_count; i++) {
        compiled_mapping_t *rule      = &ldfl_compiled_rules[i];
        uint64_t            operation = rule->mapping->operation;

        int index = ldfl_op_index(operation);
        if (latest_match[index]) {
            ldfl_setting.logger(LDFL_LOG_MAPPING_RULE_SEARCH, LOG_DEBUG,
                                "rule[name: '%s', operation: '%s']' previous identical operation rule[name: '%s', "
                                "operation: '%s'] already matched "
                                "for call[fn: '%s', path: '%s']",
                                ldfl_mapping[i].name, ldfl_operation_to_string(operation),
                                latest_rules[index]->mapping->name,
                                ldfl_operation_to_string(latest_rules[index]->mapping->operation), call, pathname);
            continue;
        }

        // Filter out rules that don’t match the op_mask or don't have regex
        if (!(operation & op_mask) || rule->matching_regex == NULL) {
            ldfl_setting.logger(
                LDFL_LOG_MAPPING_RULE_SEARCH, LOG_DEBUG,
                "rule[name: '%s', operation: '%s']', irrelevant operation for call[fn: '%s', path: '%s']",
                ldfl_mapping[i].name, ldfl_operation_to_string(operation), call, pathname);
            continue;
        }

        pcre2_match_data *match_data = pcre2_match_data_create_from_pattern(rule->matching_regex, NULL);
        int rc = pcre2_match(rule->matching_regex, (PCRE2_SPTR)pathname, strlen(pathname), 0, 0, match_data, NULL);

        if (rc <= 0) {
            ldfl_setting.logger(LDFL_LOG_MAPPING_RULE_SEARCH, LOG_DEBUG,
                                "rule[name: '%s', operation: '%s']' not matching call[fn: '%s', path: '%s']",
                                ldfl_mapping[i].name, ldfl_operation_to_string(operation), call, pathname);
            pcre2_match_data_free(match_data);
            continue;
        }

        count++;
        latest_rules[index] = rule;
        latest_match[index] = match_data;
        ldfl_setting.logger(LDFL_LOG_MAPPING_RULE_FOUND, LOG_INFO,
                            "rule[name: '%s', operation: '%s']' selected for call[fn: '%s', path: '%s']",
                            ldfl_mapping[i].name, ldfl_operation_to_string(operation), call, pathname);
    }

    *return_rules      = calloc(sizeof(compiled_mapping_t *), count);
    *return_pcre_match = calloc(sizeof(pcre2_match_data *), count);

    // Format the results
    int index = 0;
    for (int i = 0; i < 64; i++) {
        if (latest_rules[i]) {
            (*return_rules)[index]      = latest_rules[i];
            (*return_pcre_match)[index] = latest_match[i];
            index++;
        }
    }

    *num_rules = count;
    return (count > 0);
}

char *ldfl_fullpath(int dirfd, const char *pathname) {
    char *resolved_path = NULL;

    if (!pathname) {
        errno = EINVAL; // Invalid argument
        return NULL;
    }

    if (pathname[0] == '/') {
        // Absolute path
        resolved_path = realpath(pathname, NULL);
    } else {
        char dir_path[PATH_MAX];

        if (dirfd == AT_FDCWD) {
            // Use current working directory
            if (getcwd(dir_path, sizeof(dir_path)) == NULL) {
                perror("getcwd");
                return NULL;
            }
        } else {
#if defined(__APPLE__)
            // macOS: Use fstatat to resolve the directory
            struct stat dir_stat;
            if (fstatat(dirfd, "", &dir_stat, AT_EMPTY_PATH) == -1) {
                perror("fstatat");
                return NULL;
            }
            if (realpath("/proc/self/fd", dir_path) == NULL) {
                return NULL;
            }

#else
            // Linux: Resolve the directory from the file descriptor using /proc/self/fd
            char fd_path[PATH_MAX];
            sprintf(fd_path, "/proc/self/fd/%d", dirfd);
            ssize_t len = readlink(fd_path, dir_path, sizeof(dir_path) - 1);
            if (len == -1) {
                perror("readlink");
                return NULL;
            }
            dir_path[len] = '\0'; // Null-terminate the path
#endif
        }

        // Combine dir_path and pathname
        char *combined_path = calloc(PATH_MAX, sizeof(char));
        if (snprintf(combined_path, PATH_MAX, "%s/%s", dir_path, pathname) >= sizeof(combined_path)) {
            errno = ENAMETOOLONG;
            free(combined_path);
            return NULL;
        }

        resolved_path = realpath(combined_path, NULL);
        free(combined_path);
    }

    if (!resolved_path) {
        perror("realpath");
    }

    return resolved_path;
}

// Helper function for path substitution
static char *ldfl_substitute_path(pcre2_code *regex, pcre2_match_data *match_data, const char *pathname,
                                  const char *target) {
    char *new_pathname = calloc(sizeof(char), PATH_MAX);
    if (!new_pathname) {
        return NULL;
    }

    PCRE2_SIZE replacement_len = PATH_MAX;
    int        rc = pcre2_substitute(regex, (PCRE2_SPTR)pathname, PCRE2_ZERO_TERMINATED, 0, PCRE2_SUBSTITUTE_GLOBAL,
                                     match_data, NULL, (PCRE2_SPTR)target, PCRE2_ZERO_TERMINATED, (PCRE2_UCHAR *)new_pathname,
                                     &replacement_len);

    if (rc < 0 || replacement_len <= 0) {
        free(new_pathname);
        return NULL;
    }

    return new_pathname;
}

void ldfl_apply_rules(compiled_mapping_t **mapping_rules, int num_rules, pcre2_match_data **match_group,
                      const char *pathname_in, char **pathname_out) {
    if (pathname_in == NULL) {
        *pathname_out = calloc(sizeof(char), 1);
        return;
    }
    if (num_rules <= 0) {
        ldfl_setting.logger(LDFL_LOG_MAPPING_RULE_APPLY, LOG_DEBUG,
                            "No Rule to apply on path '%s', returning the same path", pathname_in);

        *pathname_out = calloc(sizeof(char), strlen(pathname_in) + 1);
        stpcpy(*pathname_out, pathname_in);
        return;
    }
    char *new_pathname;
    for (int i = 0; i < num_rules; i++) {
        switch (mapping_rules[i]->mapping->operation) {
        case LDFL_OP_NOOP:
            *pathname_out = calloc(sizeof(char), strlen(pathname_in) + 1);
            stpcpy(*pathname_out, pathname_in);
            break;
        case LDFL_OP_MAP:
            new_pathname = ldfl_substitute_path(mapping_rules[i]->matching_regex, match_group[i], pathname_in,
                                                mapping_rules[i]->mapping->target);
            if (!new_pathname) {
                ldfl_setting.logger(LDFL_LOG_MAPPING_RULE_APPLY, LOG_WARNING,
                                    "Replacement in path failed for rule '%s' on path '%s'",
                                    mapping_rules[i]->mapping->name, pathname_in);
                *pathname_out = NULL;
                return;
            }
            *pathname_out = new_pathname;

            ldfl_setting.logger(LDFL_LOG_MAPPING_RULE_APPLY, LOG_DEBUG,
                                "LDFL_OP_MAP Rule [%s] applied, path '%s' rewritten to '%s'",
                                mapping_rules[i]->mapping->name, pathname_in, *pathname_out);
            break;
        case LDFL_OP_EXEC_MAP:
            new_pathname = ldfl_substitute_path(mapping_rules[i]->matching_regex, match_group[i], pathname_in,
                                                mapping_rules[i]->mapping->target);
            if (!new_pathname) {
                ldfl_setting.logger(LDFL_LOG_MAPPING_RULE_APPLY, LOG_WARNING,
                                    "Replacement in executable path failed for rule '%s' on path '%s'",
                                    mapping_rules[i]->mapping->name, pathname_in);
                *pathname_out = NULL;
                return;
            }
            *pathname_out = new_pathname;

            ldfl_setting.logger(LDFL_LOG_MAPPING_RULE_APPLY, LOG_DEBUG,
                                "LDFL_OP_EXEC_MAP Rule [%s] applied, executable path '%s' rewritten to '%s'",
                                mapping_rules[i]->mapping->name, pathname_in, *pathname_out);
            break;
        case LDFL_OP_MEM_OPEN:
            *pathname_out = calloc(sizeof(char), strlen(pathname_in) + 1);
            stpcpy(*pathname_out, pathname_in);
            ldfl_setting.logger(LDFL_LOG_MAPPING_RULE_APPLY, LOG_WARNING, "Operation LDFL_OP_MEM_OPEN not yet handle");
            break;
        case LDFL_OP_STATIC:
            *pathname_out = calloc(sizeof(char), strlen(pathname_in) + 1);
            stpcpy(*pathname_out, pathname_in);
            ldfl_setting.logger(LDFL_LOG_MAPPING_RULE_APPLY, LOG_WARNING, "Operation LDFL_OP_STATIC not yet handle");
            break;
        case LDFL_OP_PERM:
            *pathname_out = calloc(sizeof(char), strlen(pathname_in) + 1);
            stpcpy(*pathname_out, pathname_in);
            ldfl_setting.logger(LDFL_LOG_MAPPING_RULE_APPLY, LOG_WARNING, "Operation LDFL_OP_PERM not yet handle");
            break;
        case LDFL_OP_DENY:
            *pathname_out = calloc(sizeof(char), strlen(pathname_in) + 1);
            stpcpy(*pathname_out, pathname_in);
            ldfl_setting.logger(LDFL_LOG_MAPPING_RULE_APPLY, LOG_WARNING, "Operation LDFL_OP_DENY not yet handle");
            break;
        default:
            *pathname_out = calloc(sizeof(char), strlen(pathname_in) + 1);
            stpcpy(*pathname_out, pathname_in);
            ldfl_setting.logger(LDFL_LOG_MAPPING_RULE_APPLY, LOG_WARNING, "Unknown operation %d not yet handle",
                                mapping_rules[i]->mapping->operation);
            return; // FIXME (don't only apply the first rule)
        }
    }
}

// Macro used for testing
// this permits to test the utils function without enabling the libc wrappers.
#ifndef LDLF_UTILS_TESTING

#define REAL(f)                                                                                                        \
    real_##f = dlsym(RTLD_NEXT, #f);                                                                                   \
    assert(real_##f != NULL)

#define RINIT                                                                                                          \
    if (!ldfl_initialized && !ldfl_in_init) {                                                                          \
        ldfl_setting.logger(LDFL_LOG_INIT, LOG_DEBUG, "ldld init did not run, re-init");                               \
        ldfl_init();                                                                                                   \
    };

// Flag to check if ldfl is properly initialized
// FIXME concurrency issue, add some locking when doing the init
bool ldfl_initialized;
bool ldfl_in_init;

// libc functions doing the real job
FILE *(*real_fopen)(const char *restrict pathname, const char *restrict mode);
FILE *(*real_fopen64)(const char *restrict pathname, const char *restrict mode);
FILE *(*real_freopen)(const char *restrict pathname, const char *restrict mode, FILE *restrict stream);
int (*real_creat)(const char *pathname, mode_t mode);
int (*real_open)(const char *pathname, int flags, ... /* mode_t mode */);
int (*real_open64)(const char *pathname, int flags, ... /* mode_t mode */);
int (*real_openat)(int dirfd, const char *pathname, int flags, ... /* mode_t mode */);
int (*real_openat64)(int dirfd, const char *pathname, int flags, ... /* mode_t mode */);
int (*real_rename)(const char *oldpath, const char *newpath);
int (*real_renameat2)(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags);
int (*real_renameat)(int olddirfd, const char *oldpath, int newdirfd, const char *newpath);
int (*real_unlink)(const char *pathname);
int (*real_unlinkat)(int dirfd, const char *pathname, int flags);
int (*real_utime)(const char *filename, const struct utimbuf *times);
int (*real_utimes)(const char *filename, const struct timeval times[2]);
int (*real_utimensat)(int dirfd, const char *pathname, const struct timespec times[2], int flags);
int (*real_access)(const char *pathname, int mode);
int (*real_faccessat)(int dirfd, const char *pathname, int mode, int flags);
int (*real_stat)(const char *pathname, struct stat *statbuf);
int (*real_lstat)(const char *pathname, struct stat *statbuf);
int (*real_fstatat)(int dirfd, const char *pathname, struct stat *statbuf, int flags);
int (*real_lstat)(const char *restrict pathname, struct stat *restrict statbuf);
int (*real_statx)(int dirfd, const char *restrict pathname, int flags, unsigned int mask,
                  struct statx *restrict statxbuf);
int (*real___xstat)(int version, const char *pathname, struct stat *statbuf);
int (*real___xstat64)(int version, const char *pathname, struct stat *statbuf);
int (*real___lxstat)(int version, const char *pathname, struct stat *statbuf);
int (*real___fxstatat)(int version, int dirfd, const char *pathname, struct stat *statbuf, int flags);
int (*real_execve)(const char *pathname, char *const argv[], char *const envp[]);
int (*real_execl)(const char *pathname, const char *arg, ...);
int (*real_execlp)(const char *file, const char *arg, ...);
int (*real_execv)(const char *pathname, char *const argv[]);
int (*real_execvp)(const char *file, char *const argv[]);
int (*real_glob)(const char *pattern, int flags, int (*errfunc)(const char *, int), glob_t *pglob);
ssize_t (*real_readlink)(const char *restrict pathname, char *restrict buf, size_t bufsiz);
ssize_t (*real_readlinkat)(int dirfd, const char *restrict pathname, char *restrict buf, size_t bufsiz);
DIR *(*real_opendir)(const char *name);
int (*real_mkdir)(const char *pathname, mode_t mode);
int (*real_mkdirat)(int dirfd, const char *pathname, mode_t mode);
int (*real_rmdir)(const char *pathname);
int (*real_chdir)(const char *pathname);
int (*real_symlink)(const char *target, const char *linkpathname);
int (*real_symlinkat)(const char *target, int newdirfd, const char *linkpathname);
int (*real_link)(const char *oldpath, const char *newpath);
int (*real_linkat)(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags);
int (*real_chmod)(const char *pathname, mode_t mode);
int (*real_fchmodat)(int dirfd, const char *pathname, mode_t mode, int flags);
int (*real_chown)(const char *pathname, uid_t owner, gid_t group);
int (*real_lchown)(const char *pathname, uid_t owner, gid_t group);
int (*real_truncate)(const char *pathname, off_t length);
int (*real_mkfifo)(const char *pathname, mode_t mode);
int (*real_mkfifoat)(int dirfd, const char *pathname, mode_t mode);
int (*real_mknod)(const char *pathname, mode_t mode, dev_t dev);
int (*real_mknodat)(int dirfd, const char *pathname, mode_t mode, dev_t dev);

// DIR *(*real_fdopendir)(int fd);
// int (*real_fchdir)(int fd);
// int (*real_fchmod)(int fd, mode_t mode);
// int (*real_futimes)(int fd, const struct timeval times[2]);
// int (*real_futimens)(int fd, const struct timespec times[2]);
// int (*real_ftruncate)(int fd, off_t length);
// int (*real_fstat)(int fd, struct stat *statbuf);
// int (*real___fxstat)(int version, int fd, struct stat *statbuf);
// int (*real_fchmod)(int fd, mode_t mode);
// char *(*real_getcwd)(char *buf, size_t size);
// off_t (*real_lseek)(int fd, off_t offset, int whence);

#if defined(__APPLE__)
int (*real_renamex_np)(const char *oldpath, const char *newpath, int flags);
int (*real_renameatx_np)(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags);
#endif

// init function
// dlsym the real libc functions & compile the matching regex
// FIXME concurrency issue
static void __attribute__((constructor(101))) ldfl_init() {
    ldfl_in_init = true;

    REAL(fopen);
    REAL(fopen64);
    REAL(freopen);
    REAL(creat);
    REAL(open);
    REAL(open64);
    REAL(openat);
    REAL(openat64);
    REAL(rename);
    REAL(renameat2);
    REAL(renameat);
    REAL(unlink);
    REAL(unlinkat);
    REAL(utime);
    REAL(utimes);
    REAL(utimensat);
    REAL(access);
    REAL(faccessat);
    REAL(stat);
    REAL(lstat);
    REAL(fstatat);
    REAL(lstat);
    REAL(statx);
    REAL(__xstat);
    REAL(__xstat64);
    REAL(__lxstat);
    REAL(__fxstatat);
    REAL(execve);
    REAL(execl);
    REAL(execlp);
    REAL(execv);
    REAL(execvp);
    REAL(glob);
    REAL(readlink);
    REAL(readlinkat);
    REAL(opendir);
    REAL(mkdir);
    REAL(mkdirat);
    REAL(rmdir);
    REAL(chdir);
    REAL(symlink);
    REAL(symlinkat);
    REAL(link);
    REAL(linkat);
    REAL(chmod);
    REAL(fchmodat);
    REAL(chown);
    REAL(lchown);
    REAL(truncate);
    REAL(mkfifo);
    REAL(mkfifoat);
    REAL(mknod);
    REAL(mknodat);
#if defined(__APPLE__)
    REAL(renamex_np);
    REAL(renameatx_np);
#endif

#ifndef LDFL_CONFIG
    ldfl_regex_free();
    const char *config_path = getenv("LDFL_CONFIG");
    if (config_path == NULL)
        ldfl_setting.logger(LDFL_LOG_INIT, LOG_WARNING, "LDFL_CONFIG environment variable is not set");
    if (config_path != NULL && ldfl_parse_json_config(config_path))
        ldfl_setting.logger(LDFL_LOG_INIT, LOG_WARNING, "Failed to load JSON config '%s'", config_path);
    ldfl_setting.logger(LDFL_LOG_INIT, LOG_DEBUG, "ldfl init called");
    ldfl_regex_init();
    if (ldfl_mapping != default_default)
        ldfl_initialized = true;
#else
    ldfl_setting.logger(LDFL_LOG_INIT, LOG_DEBUG, "ldfl init called");
    ldfl_regex_init();
    ldfl_initialized = true;
#endif

    ldfl_in_init = false;
    ldfl_setting.logger(LDFL_LOG_INIT, LOG_DEBUG, "initialized");
}

#define LDFL_LOG_ERR(expr, fmt, ...)                                                                                   \
    if (!(expr)) {                                                                                                     \
        ldfl_setting.logger(LDFL_LOG_FN_CALL_ERR, LOG_ERR, fmt, ##__VA_ARGS__);                                        \
    }

#define LDFL_LOG_CALL(...) ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, ##__VA_ARGS__)

char *apply_rules_and_cleanup(char *func_name, const char *pathname, uint64_t op_mask) {
    char                *reworked_path     = NULL;
    compiled_mapping_t **return_rules      = NULL;
    pcre2_match_data   **return_pcre_match = NULL;
    int                  num_rules         = 0;
    ldfl_find_matching_rules(func_name, pathname, op_mask, &return_rules, &num_rules, &return_pcre_match);
    ldfl_apply_rules(return_rules, num_rules, return_pcre_match, pathname, &reworked_path);
    for (int i = 0; i < num_rules; i++) {
        pcre2_match_data_free(return_pcre_match[i]);
    }
    free(return_rules);
    free(return_pcre_match);
    return reworked_path;
}

// de-init function
// free compiled regexp
static void __attribute__((destructor(101))) ldfl_dinit() {
    ldfl_setting.logger(LDFL_LOG_INIT, LOG_DEBUG, "ldfl dinit called");
    ldfl_regex_free();
#ifndef LDFL_CONFIG
    ldfl_free_json_config();
#endif
    ldfl_setting.logger(LDFL_LOG_INIT, LOG_DEBUG, "freed");
}

FILE *fopen(const char *restrict pathname, const char *restrict mode) {
    RINIT;
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_RO | LDFL_OP_PERM | LDFL_OP_DENY;

    LDFL_LOG_CALL("fopen called: pathname=%s, mode=%s", pathname, mode);

    char *reworked_path = apply_rules_and_cleanup("fopen", pathname, op_mask);
    FILE *ret           = real_fopen(reworked_path, mode);

    LDFL_LOG_ERR(ret, "real_fopen failed: pathname=%s, mode=%s, errno=%d (%s)", reworked_path, mode, errno,
                 strerror(errno));

    free(reworked_path);
    return ret;
}

FILE *fopen64(const char *pathname, const char *mode) {
    RINIT;
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_RO | LDFL_OP_PERM | LDFL_OP_DENY;

    LDFL_LOG_CALL("fopen64 called: pathname=%s, mode=%s", pathname, mode);

    char *reworked_path = apply_rules_and_cleanup("fopen64", pathname, op_mask);
    FILE *ret           = real_fopen64(reworked_path, mode);

    LDFL_LOG_ERR(ret, "real_fopen64 failed: pathname=%s, mode=%s, errno=%d (%s)", reworked_path, mode, errno,
                 strerror(errno));

    free(reworked_path);
    return ret;
}

int openat(int dirfd, const char *pathname, int flags, ...) {
    RINIT;
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_RO | LDFL_OP_PERM | LDFL_OP_DENY;
    va_list args;
    va_start(args, flags);

    LDFL_LOG_CALL("openat called: dirfd=%d, pathname=%s, flags=%d, mode=%o", dirfd, pathname, flags,
                  va_arg(args, mode_t));

    char *reworked_path = apply_rules_and_cleanup("openat", pathname, op_mask);
    int ret = ldfl_variadic_mode_wrap(real_openat, dirfd, reworked_path, flags);

    LDFL_LOG_ERR(ret, "real_openat failed: dirfd=%d, pathname=%s, flags=%d, errno=%d (%s)", dirfd, reworked_path, flags,
                 errno, strerror(errno));

    free(reworked_path);
    va_end(args);
    return ret;
}

int open(const char *pathname, int flags, ... /* mode_t mode */) {
    RINIT;
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_RO | LDFL_OP_PERM | LDFL_OP_DENY;
    va_list args;
    va_start(args, flags);

    LDFL_LOG_CALL("open called: pathname=%s, flags=%d, mode=%o", pathname, flags, va_arg(args, mode_t));

    char *reworked_path = apply_rules_and_cleanup("open", pathname, op_mask);
    int   ret           = ldfl_variadic_mode_wrap(real_open, reworked_path, flags);

    LDFL_LOG_ERR(ret, "real_open failed: pathname=%s, flags=%d, errno=%d (%s)", reworked_path, flags, errno,
                 strerror(errno));

    free(reworked_path);
    va_end(args);
    return ret;
}

int open64(const char *pathname, int flags, ... /* mode_t mode */) {
    RINIT;
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_RO | LDFL_OP_PERM | LDFL_OP_DENY;
    va_list args;
    va_start(args, flags);

    LDFL_LOG_CALL("open64 called: pathname=%s, flags=%d, mode=%o", pathname, flags, va_arg(args, mode_t));

    char *reworked_path = apply_rules_and_cleanup("open64", pathname, op_mask);
    int   ret           = ldfl_variadic_mode_wrap(real_open64, reworked_path, flags);

    LDFL_LOG_ERR(ret, "real_open64 failed: pathname=%s, flags=%d, errno=%d (%s)", reworked_path, flags, errno,
                 strerror(errno));

    free(reworked_path);
    va_end(args);
    return ret;
}

int openat64(int dirfd, const char *pathname, int flags, ... /* mode_t mode */) {
    RINIT;
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_RO | LDFL_OP_PERM | LDFL_OP_DENY;
    va_list args;
    va_start(args, flags);

    LDFL_LOG_CALL("openat64 called: dirfd=%d, pathname=%s, flags=%d, mode=%o", dirfd, pathname, flags,
                  va_arg(args, mode_t));
    char *reworked_path = apply_rules_and_cleanup("openat64", pathname, op_mask);
    int   ret           = ldfl_variadic_mode_wrap(real_openat64, dirfd, reworked_path, flags);

    LDFL_LOG_ERR(ret, "real_openat64 failed: dirfd=%d, pathname=%s, flags=%d, errno=%d (%s)", dirfd, reworked_path,
                 flags, errno, strerror(errno));

    va_end(args);
    free(reworked_path);
    return ret;
}

int rename(const char *oldpath, const char *newpath) {
    RINIT;
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_RO | LDFL_OP_PERM | LDFL_OP_DENY;

    LDFL_LOG_CALL("rename called: oldpath=%s, newpath=%s", oldpath, newpath);

    char *reworked_oldpath = apply_rules_and_cleanup("rename", oldpath, op_mask);
    char *reworked_newpath = apply_rules_and_cleanup("rename", newpath, op_mask);
    int   ret              = real_rename(reworked_oldpath, reworked_newpath);

    LDFL_LOG_ERR(ret, "real_rename failed: oldpath=%s, newpath=%s, errno=%d (%s)", reworked_oldpath, reworked_newpath,
                 errno, strerror(errno));

    free(reworked_oldpath);
    free(reworked_newpath);
    return ret;
}

int renameat2(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags) {
    RINIT;
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_RO | LDFL_OP_PERM | LDFL_OP_DENY;

    LDFL_LOG_CALL("renameat2 called: olddirfd=%d, oldpath=%s, newdirfd=%d, newpath=%s, flags=%u", olddirfd, oldpath,
                  newdirfd, newpath, flags);

    char *reworked_oldpath = apply_rules_and_cleanup("renameat2", oldpath, op_mask);
    char *reworked_newpath = apply_rules_and_cleanup("renameat2", newpath, op_mask);
    int   ret              = real_renameat2(olddirfd, reworked_oldpath, newdirfd, reworked_newpath, flags);

    LDFL_LOG_ERR(ret,
                 "real_renameat2 failed: olddirfd=%d, oldpath=%s, newdirfd=%d, newpath=%s, flags=%d, "
                 "errno=%d (%s)",
                 olddirfd, reworked_oldpath, newdirfd, reworked_newpath, flags, errno, strerror(errno));

    free(reworked_oldpath);
    free(reworked_newpath);
    return ret;
}

int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath) {
    RINIT;
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_RO | LDFL_OP_PERM | LDFL_OP_DENY;

    LDFL_LOG_CALL("renameat called: olddirfd=%d, oldpath=%s, newdirfd=%d, newpath=%s", olddirfd, oldpath, newdirfd,
                  newpath);

    char *reworked_oldpath = apply_rules_and_cleanup("renameat", oldpath, op_mask);
    char *reworked_newpath = apply_rules_and_cleanup("renameat", newpath, op_mask);
    int   ret              = real_renameat(olddirfd, reworked_oldpath, newdirfd, reworked_newpath);

    LDFL_LOG_ERR(ret, "real_renameat failed: olddirfd=%d, oldpath=%s, newdirfd=%d, newpath=%s, errno=%d (%s)", olddirfd,
                 reworked_oldpath, newdirfd, reworked_newpath, errno, strerror(errno));

    free(reworked_oldpath);
    free(reworked_newpath);
    return ret;
}

int unlink(const char *pathname) {
    RINIT;
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_RO | LDFL_OP_PERM | LDFL_OP_DENY;

    LDFL_LOG_CALL("unlink called: pathname=%s", pathname);

    char *reworked_path = apply_rules_and_cleanup("unlink", pathname, op_mask);
    int   ret           = real_unlink(reworked_path);

    LDFL_LOG_ERR(ret, "real_unlink failed: pathname=%s, errno=%d (%s)", reworked_path, errno, strerror(errno));

    free(reworked_path);
    return ret;
}

int unlinkat(int dirfd, const char *pathname, int flags) {
    RINIT;
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_RO | LDFL_OP_PERM | LDFL_OP_DENY;

    LDFL_LOG_CALL("unlinkat called: dirfd=%d, pathname=%s, flags=%d", dirfd, pathname, flags);

    char *reworked_path = apply_rules_and_cleanup("unlinkat", pathname, op_mask);
    int   ret           = real_unlinkat(dirfd, reworked_path, flags);

    LDFL_LOG_ERR(ret == 0, "real_unlinkat failed: dirfd=%d, pathname=%s, flags=%d, errno=%d (%s)", dirfd, reworked_path,
                 flags, errno, strerror(errno));

    free(reworked_path);
    return ret;
}

int utime(const char *pathname, const struct utimbuf *times) {
    RINIT;
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_RO | LDFL_OP_PERM | LDFL_OP_DENY;

    LDFL_LOG_CALL("utimes called: pathname=%s, times=[%ld, %ld]", pathname, (times == NULL) ? 0 : times->actime,
                  (times == NULL) ? 0 : times->modtime);

    char *reworked_path = apply_rules_and_cleanup("utime", pathname, op_mask);
    int   ret           = real_utime(reworked_path, times);

    LDFL_LOG_ERR(ret == 0, "real_utime failed: pathname=%s, errno=%d (%s)", reworked_path, errno, strerror(errno));

    free(reworked_path);
    return ret;
}

int utimes(const char *pathname, const struct timeval times[2]) {
    RINIT;
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_RO | LDFL_OP_PERM | LDFL_OP_DENY;

    LDFL_LOG_CALL("utimes called: pathname=%s, times=[%ld:%ld, %ld:%ld]", pathname,
                  (times == NULL) ? 0 : times[0].tv_sec, (times == NULL) ? 0 : times[0].tv_usec,
                  (times == NULL) ? 0 : times[1].tv_sec, (times == NULL) ? 0 : times[1].tv_usec);

    char *reworked_path = apply_rules_and_cleanup("utimes", pathname, op_mask);
    int   ret           = real_utimes(reworked_path, times);

    LDFL_LOG_ERR(ret == 0, "real_utimes failed: pathname=%s, errno=%d (%s)", reworked_path, errno, strerror(errno));

    free(reworked_path);
    return ret;
}

int utimensat(int dirfd, const char *pathname, const struct timespec times[2], int flags) {
    RINIT;
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_RO | LDFL_OP_PERM | LDFL_OP_DENY;

    LDFL_LOG_CALL("utimensat called: dirfd=%d, pathname=%s, times=[%ld, %ld], flags=%d", dirfd, pathname,
                  (times == NULL) ? 0 : times[0].tv_sec, (times == NULL) ? 0 : times[1].tv_sec, flags);

    char *reworked_path = apply_rules_and_cleanup("utimensat", pathname, op_mask);
    int   ret           = real_utimensat(dirfd, reworked_path, times, flags);

    LDFL_LOG_ERR(ret == 0, "real_utimensat failed: dirfd=%d, pathname=%s, flags=%d, errno=%d (%s)", dirfd, pathname,
                 flags, errno, strerror(errno));

    free(reworked_path);
    return ret;
}

int access(const char *pathname, int mode) {
    RINIT;
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_RO | LDFL_OP_PERM | LDFL_OP_DENY;

    LDFL_LOG_CALL("access called: pathname=%s, mode=%d", pathname, mode);

    char *reworked_path = apply_rules_and_cleanup("access", pathname, op_mask);
    int   ret           = real_access(reworked_path, mode);

    LDFL_LOG_ERR(ret == 0, "real_access failed: pathname=%s, mode=%d, errno=%d (%s)", reworked_path, mode, errno,
                 strerror(errno));

    free(reworked_path);
    return ret;
}

int fstatat(int dirfd, const char *pathname, struct stat *statbuf, int flags) {
    RINIT;
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_RO | LDFL_OP_PERM | LDFL_OP_DENY;

    LDFL_LOG_CALL("fstatat called: dirfd=%d, pathname=%s, flags=%d", dirfd, pathname, flags);

    char *reworked_path = apply_rules_and_cleanup("fstatat", pathname, op_mask);
    int   ret           = real_fstatat(dirfd, reworked_path, statbuf, flags);

    LDFL_LOG_ERR(ret == 0, "real_fstatat failed: dirfd=%d, pathname=%s, flags=%d, errno=%d (%s)", dirfd, pathname,
                 flags, errno, strerror(errno));

    free(reworked_path);
    return ret;
}

int __xstat(int version, const char *pathname, struct stat *statbuf) {
    RINIT;
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_RO | LDFL_OP_PERM | LDFL_OP_DENY;

    LDFL_LOG_CALL("__xstat called: version=%d, pathname=%s", version, pathname);

    char *reworked_path = apply_rules_and_cleanup("__xstat", pathname, op_mask);
    int   ret           = real___xstat(version, reworked_path, statbuf);

    LDFL_LOG_ERR(ret == 0, "real___xstat failed: version=%d, pathname=%s, errno=%d (%s)", version, pathname, errno,
                 strerror(errno));

    free(reworked_path);
    return ret;
}

int __xstat64(int version, const char *pathname, struct stat *statbuf) {
    RINIT;
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_RO | LDFL_OP_PERM | LDFL_OP_DENY;

    LDFL_LOG_CALL("__xstat64 called: version=%d, pathname=%s", version, pathname);

    char *reworked_path = apply_rules_and_cleanup("__xstat64", pathname, op_mask);
    int   ret           = real___xstat64(version, reworked_path, statbuf);

    LDFL_LOG_ERR(ret == 0, "real___xstat64 failed: version=%d, pathname=%s, errno=%d (%s)", version, pathname, errno,
                 strerror(errno));

    free(reworked_path);
    return ret;
}

int __lxstat(int version, const char *pathname, struct stat *statbuf) {
    RINIT;
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_RO | LDFL_OP_PERM | LDFL_OP_DENY;

    LDFL_LOG_CALL("__lxstat called: version=%d, pathname=%s", version, pathname);

    char *reworked_path = apply_rules_and_cleanup("__lxstat", pathname, op_mask);
    int   ret           = real___lxstat(version, reworked_path, statbuf);

    LDFL_LOG_ERR(ret == 0, "real___lxstat failed: version=%d, pathname=%s, errno=%d (%s)", version, pathname, errno,
                 strerror(errno));

    free(reworked_path);
    return ret;
}

int __fxstatat(int version, int dirfd, const char *pathname, struct stat *statbuf, int flags) {
    RINIT;
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_RO | LDFL_OP_PERM | LDFL_OP_DENY;

    LDFL_LOG_CALL("__fxstatat called: version=%d, dirfd=%d, pathname=%s, flags=%d", version, dirfd, pathname, flags);

    char *reworked_path = apply_rules_and_cleanup("__fxstatat", pathname, op_mask);
    int   ret           = real___fxstatat(version, dirfd, reworked_path, statbuf, flags);

    LDFL_LOG_ERR(ret == 0, "real___fxstatat failed: version=%d, dirfd=%d, pathname=%s, flags=%d, errno=%d (%s)",
                 version, dirfd, pathname, flags, errno, strerror(errno));

    free(reworked_path);
    return ret;
}

int execve(const char *pathname, char *const argv[], char *const envp[]) {
    RINIT;
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_EXEC_MAP | LDFL_OP_DENY;

    char *argv_str = ldfl_render_nullable_array(argv);
    char *envp_str = ldfl_render_nullable_array(envp);

    LDFL_LOG_CALL("execve called: pathname=%s, argv=%s, envp=%s", pathname, argv_str, envp_str);

    char *reworked_path  = apply_rules_and_cleanup("execve", pathname, op_mask);
    char *original_argv0 = NULL;
    if (reworked_path && strcmp(pathname, reworked_path) != 0 && argv[0]) {
        original_argv0     = argv[0];
        ((char **)argv)[0] = reworked_path;
    }
    int ret = real_execve(reworked_path, argv, envp);

    LDFL_LOG_ERR(ret == 0, "real_execve failed: pathname=%s, errno=%d (%s)", reworked_path, errno, strerror(errno));

    if (original_argv0) {
        ((char **)argv)[0] = original_argv0;
    }
    free(reworked_path);
    free(argv_str);
    free(envp_str);
    return ret;
}

int execl(const char *pathname, const char *arg, ...) {
    RINIT;
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_EXEC_MAP | LDFL_OP_DENY;
    va_list  args;
    va_start(args, arg);

    LDFL_LOG_CALL("execl called: pathname=%s, arg=%s", pathname, arg);

    char *reworked_path = apply_rules_and_cleanup("execl", pathname, op_mask);
    char *original_arg  = NULL;
    if (reworked_path && strcmp(pathname, reworked_path) != 0) {
        original_arg = (char *)arg;
        arg          = reworked_path;
    }
    int ret = ldfl_variadic_str_wrap(real_execl, arg, reworked_path, arg);

    LDFL_LOG_ERR(ret == 0, "real_execl failed: pathname=%s, errno=%d (%s)", reworked_path, errno, strerror(errno));

    if (original_arg) {
        arg = original_arg;
    }
    free(reworked_path);
    va_end(args);
    return ret;
}

int execlp(const char *file, const char *arg, ...) {
    RINIT;
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_EXEC_MAP | LDFL_OP_DENY;
    va_list  args;
    va_start(args, arg);

    LDFL_LOG_CALL("execlp called: file=%s, arg=%s", file, arg);

    char *reworked_path = apply_rules_and_cleanup("execlp", file, op_mask);
    char *original_arg  = NULL;
    if (reworked_path && strcmp(file, reworked_path) != 0) {
        original_arg = (char *)arg;
        arg          = reworked_path;
    }
    int ret = ldfl_variadic_str_wrap(real_execlp, arg, reworked_path, arg);

    LDFL_LOG_ERR(ret == 0, "real_execlp failed: pathname=%s, errno=%d (%s)", reworked_path, errno, strerror(errno));

    if (original_arg) {
        arg = original_arg;
    }
    free(reworked_path);
    va_end(args);
    return ret;
}

int execv(const char *pathname, char *const argv[]) {
    RINIT;
    uint64_t op_mask  = LDFL_OP_NOOP | LDFL_OP_EXEC_MAP | LDFL_OP_DENY;
    char    *argv_str = ldfl_render_nullable_array(argv);

    LDFL_LOG_CALL("execv called: pathname=%s, argv=%s", pathname, argv_str);

    char *reworked_path  = apply_rules_and_cleanup("execv", pathname, op_mask);
    char *original_argv0 = NULL;
    if (reworked_path && strcmp(pathname, reworked_path) != 0 && argv[0]) {
        original_argv0     = argv[0];
        ((char **)argv)[0] = reworked_path;
    }
    int ret = real_execv(reworked_path, argv);

    LDFL_LOG_ERR(ret == 0, "real_execv failed: pathname=%s, errno=%d (%s)", reworked_path, errno, strerror(errno));

    if (original_argv0) {
        ((char **)argv)[0] = original_argv0;
    }
    free(reworked_path);
    free(argv_str);
    return ret;
}

int execvp(const char *file, char *const argv[]) {
    RINIT;
    uint64_t op_mask  = LDFL_OP_NOOP | LDFL_OP_EXEC_MAP | LDFL_OP_DENY;
    char    *argv_str = ldfl_render_nullable_array(argv);

    LDFL_LOG_CALL("execvp called: file=%s, argv=%s", file, argv_str);

    char *reworked_path  = apply_rules_and_cleanup("execvp", file, op_mask);
    char *original_argv0 = NULL;
    if (reworked_path && strcmp(file, reworked_path) != 0 && argv[0]) {
        original_argv0     = argv[0];
        ((char **)argv)[0] = reworked_path;
    }
    int ret = real_execvp(reworked_path, argv);

    LDFL_LOG_ERR(ret == 0, "real_execvp failed: pathname=%s, errno=%d (%s)", reworked_path, errno, strerror(errno));

    if (original_argv0) {
        ((char **)argv)[0] = original_argv0;
    }
    free(reworked_path);
    free(argv_str);
    return ret;
}

DIR *opendir(const char *name) {
    RINIT;
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_RO | LDFL_OP_PERM | LDFL_OP_DENY;

    LDFL_LOG_CALL("opendir called: name=%s", name);

    char *reworked_path = apply_rules_and_cleanup("opendir", name, op_mask);
    DIR  *ret           = real_opendir(reworked_path);

    LDFL_LOG_ERR(ret != NULL, "real_opendir failed: pathname=%s, errno=%d (%s)", reworked_path, errno, strerror(errno));

    free(reworked_path);
    return ret;
}

int mkdir(const char *pathname, mode_t mode) {
    RINIT;
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_RO | LDFL_OP_PERM | LDFL_OP_DENY;

    LDFL_LOG_CALL("mkdir called: pathname=%s, mode=%o", pathname, mode);

    char *reworked_path = apply_rules_and_cleanup("mkdir", pathname, op_mask);
    int   ret           = real_mkdir(reworked_path, mode);

    LDFL_LOG_ERR(ret == 0, "real_mkdir failed: pathname=%s, mode=%d, errno=%d (%s)", reworked_path, mode, errno,
                 strerror(errno));

    free(reworked_path);
    return ret;
}

int mkdirat(int dirfd, const char *pathname, mode_t mode) {
    RINIT;
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_RO | LDFL_OP_PERM | LDFL_OP_DENY;

    LDFL_LOG_CALL("mkdirat called: dirfd=%d, pathname=%s, mode=%o", dirfd, pathname, mode);

    char *reworked_path = apply_rules_and_cleanup("mkdirat", pathname, op_mask);
    int   ret           = real_mkdirat(dirfd, reworked_path, mode);

    LDFL_LOG_ERR(ret == 0, "real_mkdirat failed: dirfd=%d, pathname=%s, mode=%d, errno=%d (%s)", dirfd, reworked_path,
                 mode, errno, strerror(errno));

    free(reworked_path);
    return ret;
}

int rmdir(const char *pathname) {
    RINIT;
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_RO | LDFL_OP_PERM | LDFL_OP_DENY;

    LDFL_LOG_CALL("rmdir called: pathname=%s", pathname);

    char *reworked_path = apply_rules_and_cleanup("rmdir", pathname, op_mask);
    int   ret           = real_rmdir(reworked_path);

    LDFL_LOG_ERR(ret == 0, "real_rmdir failed: pathname=%s, errno=%d (%s)", reworked_path, errno, strerror(errno));

    free(reworked_path);
    return ret;
}

int chdir(const char *pathname) {
    RINIT;
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_RO | LDFL_OP_PERM | LDFL_OP_DENY;

    LDFL_LOG_CALL("chdir called: pathname=%s", pathname);

    char *reworked_path = apply_rules_and_cleanup("chdir", pathname, op_mask);
    int   ret           = real_chdir(reworked_path);

    LDFL_LOG_ERR(ret == 0, "real_chdir failed: pathname=%s, errno=%d (%s)", reworked_path, errno, strerror(errno));

    free(reworked_path);
    return ret;
}

int symlink(const char *target, const char *linkpathname) {
    RINIT;
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_RO | LDFL_OP_PERM | LDFL_OP_DENY;

    LDFL_LOG_CALL("symlink called: target=%s, linkpathname=%s", target, linkpathname);

    char *reworked_linkpathname = apply_rules_and_cleanup("symlink", linkpathname, op_mask);
    char *reworked_target       = apply_rules_and_cleanup("symlink", target, op_mask);
    int   ret                   = real_symlink(reworked_target, reworked_linkpathname);

    LDFL_LOG_ERR(ret == 0, "real_symlink failed: target=%s, linkpathname=%s, errno=%d (%s)", reworked_target,
                 reworked_linkpathname, errno, strerror(errno));

    free(reworked_linkpathname);
    free(reworked_target);
    return ret;
}

ssize_t readlink(const char *pathname, char *buf, size_t bufsiz) {
    RINIT;
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_RO | LDFL_OP_PERM | LDFL_OP_DENY;

    LDFL_LOG_CALL("readlink called: pathname=%s, bufsiz=%zu", pathname, bufsiz);

    char *reworked_path = apply_rules_and_cleanup("readlink", pathname, op_mask);
    int   ret           = real_readlink(reworked_path, buf, bufsiz);

    LDFL_LOG_ERR(ret != -1, "real_readlink failed: pathname=%s, errno=%d (%s)", reworked_path, errno, strerror(errno));

    free(reworked_path);
    return ret;
}

int link(const char *oldpath, const char *newpath) {
    RINIT;
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_RO | LDFL_OP_PERM | LDFL_OP_DENY;

    LDFL_LOG_CALL("link called: oldpath=%s, newpath=%s", oldpath, newpath);

    char *reworked_oldpath = apply_rules_and_cleanup("link", oldpath, op_mask);
    char *reworked_newpath = apply_rules_and_cleanup("link", newpath, op_mask);
    int   ret              = real_link(reworked_oldpath, reworked_newpath);

    LDFL_LOG_ERR(ret == 0, "real_link failed: oldpath=%s, newpath=%s, errno=%d (%s)", reworked_oldpath,
                 reworked_newpath, errno, strerror(errno));

    free(reworked_oldpath);
    free(reworked_newpath);
    return ret;
}

int linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags) {
    RINIT;
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_RO | LDFL_OP_PERM | LDFL_OP_DENY;

    LDFL_LOG_CALL("linkat called: olddirfd=%d, oldpath=%s, newdirfd=%d, newpath=%s, flags=%d", olddirfd, oldpath,
                  newdirfd, newpath, flags);

    char *reworked_oldpath = apply_rules_and_cleanup("linkat", oldpath, op_mask);
    char *reworked_newpath = apply_rules_and_cleanup("linkat", newpath, op_mask);
    int   ret              = real_linkat(olddirfd, reworked_oldpath, newdirfd, reworked_newpath, flags);

    LDFL_LOG_ERR(ret == 0,
                 "real_linkat failed: olddirfd=%d, oldpath=%s, newdirfd=%d, newpath=%s, flags=%d, "
                 "errno=%d (%s)",
                 olddirfd, reworked_oldpath, newdirfd, reworked_newpath, flags, errno, strerror(errno));

    free(reworked_oldpath);
    free(reworked_newpath);
    return ret;
}

int chmod(const char *pathname, mode_t mode) {
    RINIT;
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_RO | LDFL_OP_PERM | LDFL_OP_DENY;

    LDFL_LOG_CALL("chmod called: pathname=%s, mode=%o", pathname, mode);

    char *reworked_path = apply_rules_and_cleanup("chmod", pathname, op_mask);
    int   ret           = real_chmod(reworked_path, mode);

    LDFL_LOG_ERR(ret == 0, "real_chmod failed: pathname=%s, mode=%d, errno=%d (%s)", reworked_path, mode, errno,
                 strerror(errno));

    free(reworked_path);
    return ret;
}

int truncate(const char *pathname, off_t length) {
    RINIT;
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_RO | LDFL_OP_PERM | LDFL_OP_DENY;

    LDFL_LOG_CALL("truncate called: pathname=%s, length=%ld", pathname, length);

    char *reworked_path = apply_rules_and_cleanup("truncate", pathname, op_mask);
    int   ret           = real_truncate(reworked_path, length);

    LDFL_LOG_ERR(ret == 0, "real_truncate failed: pathname=%s, length=%ld, errno=%d (%s)", reworked_path, length, errno,
                 strerror(errno));

    free(reworked_path);
    return ret;
}

int faccessat(int dirfd, const char *pathname, int mode, int flags) {
    RINIT;
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_RO | LDFL_OP_PERM | LDFL_OP_DENY;

    LDFL_LOG_CALL("faccessat called: dirfd=%d, pathname=%s, mode=%d, flags=%d", dirfd, pathname, mode, flags);

    char *reworked_path = apply_rules_and_cleanup("faccessat", pathname, op_mask);
    int   ret           = real_faccessat(dirfd, reworked_path, mode, flags);

    LDFL_LOG_ERR(ret == 0, "real_faccessat failed: dirfd=%d, pathname=%s, mode=%d, flags=%d, errno=%d (%s)", dirfd,
                 reworked_path, mode, flags, errno, strerror(errno));

    free(reworked_path);
    return ret;
}

int stat(const char *pathname, struct stat *statbuf) {
    RINIT;
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_RO | LDFL_OP_PERM | LDFL_OP_DENY;

    LDFL_LOG_CALL("stat called: pathname=%s", pathname);

    char *reworked_path = apply_rules_and_cleanup("stat", pathname, op_mask);
    int   ret           = real_stat(reworked_path, statbuf);

    LDFL_LOG_ERR(ret == 0, "real_stat failed: pathname=%s, errno=%d (%s)", reworked_path, errno, strerror(errno));

    free(reworked_path);
    return ret;
}

int lstat(const char *pathname, struct stat *statbuf) {
    RINIT;
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_RO | LDFL_OP_PERM | LDFL_OP_DENY;

    LDFL_LOG_CALL("lstat called: pathname=%s", pathname);

    char *reworked_path = apply_rules_and_cleanup("lstat", pathname, op_mask);
    int   ret           = real_lstat(reworked_path, statbuf);

    LDFL_LOG_ERR(ret == 0, "real_lstat failed: pathname=%s, errno=%d (%s)", reworked_path, errno, strerror(errno));

    free(reworked_path);
    return ret;
}

int lchown(const char *pathname, uid_t owner, gid_t group) {
    RINIT;
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_RO | LDFL_OP_PERM | LDFL_OP_DENY;

    LDFL_LOG_CALL("lchown called: pathname=%s, owner=%d, group=%d", pathname, owner, group);

    char *reworked_path = apply_rules_and_cleanup("lchown", pathname, op_mask);
    int   ret           = real_lchown(reworked_path, owner, group);

    LDFL_LOG_ERR(ret == 0, "real_lchown failed: pathname=%s, owner=%d, group=%d, errno=%d (%s)", reworked_path, owner,
                 group, errno, strerror(errno));

    free(reworked_path);
    return ret;
}

int chown(const char *pathname, uid_t owner, gid_t group) {
    RINIT;
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_RO | LDFL_OP_PERM | LDFL_OP_DENY;

    LDFL_LOG_CALL("chown called: pathname=%s, owner=%d, group=%d", pathname, owner, group);

    char *reworked_path = apply_rules_and_cleanup("chown", pathname, op_mask);
    int   ret           = real_chown(reworked_path, owner, group);

    LDFL_LOG_ERR(ret == 0, "real_chown failed: pathname=%s, owner=%d, group=%d, errno=%d (%s)", reworked_path, owner,
                 group, errno, strerror(errno));

    free(reworked_path);
    return ret;
}

int fchmodat(int dirfd, const char *pathname, mode_t mode, int flags) {
    RINIT;
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_RO | LDFL_OP_PERM | LDFL_OP_DENY;

    LDFL_LOG_CALL("fchmodat called: dirfd=%d, pathname=%s, mode=%o, flags=%d", dirfd, pathname, mode, flags);

    char *reworked_path = apply_rules_and_cleanup("fchmodat", pathname, op_mask);
    int   ret           = real_fchmodat(dirfd, reworked_path, mode, flags);

    LDFL_LOG_ERR(ret == 0, "real_fchmodat failed: dirfd=%d, pathname=%s, mode=%d, flags=%d, errno=%d (%s)", dirfd,
                 reworked_path, mode, flags, errno, strerror(errno));

    free(reworked_path);
    return ret;
}

int symlinkat(const char *target, int newdirfd, const char *linkpathname) {
    RINIT;
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_RO | LDFL_OP_PERM | LDFL_OP_DENY;

    LDFL_LOG_CALL("symlinkat called: target=%s, newdirfd=%d, linkpathname=%s", target, newdirfd, linkpathname);

    char *reworked_target       = apply_rules_and_cleanup("symlinkat", target, op_mask);
    char *reworked_linkpathname = apply_rules_and_cleanup("symlinkat", linkpathname, op_mask);
    int   ret                   = real_symlinkat(reworked_target, newdirfd, reworked_linkpathname);

    LDFL_LOG_ERR(ret == 0, "real_symlinkat failed: target=%s, newdirfd=%d, linkpathname=%s, errno=%d (%s)",
                 reworked_target, newdirfd, reworked_linkpathname, errno, strerror(errno));

    free(reworked_target);
    free(reworked_linkpathname);
    return ret;
}

int mkfifo(const char *pathname, mode_t mode) {
    RINIT;
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_RO | LDFL_OP_PERM | LDFL_OP_DENY;

    LDFL_LOG_CALL("mkfifo called: pathname=%s, mode=%o", pathname, mode);

    char *reworked_path = apply_rules_and_cleanup("mkfifo", pathname, op_mask);
    int   ret           = real_mkfifo(reworked_path, mode);

    LDFL_LOG_ERR(ret == 0, "real_mkfifo failed: pathname=%s, mode=%d, errno=%d (%s)", reworked_path, mode, errno,
                 strerror(errno));

    free(reworked_path);
    return ret;
}

int mkfifoat(int dirfd, const char *pathname, mode_t mode) {
    RINIT;
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_RO | LDFL_OP_PERM | LDFL_OP_DENY;

    LDFL_LOG_CALL("mkfifoat called: dirfd=%d, pathname=%s, mode=%o", dirfd, pathname, mode);

    char *reworked_path = apply_rules_and_cleanup("mkfifoat", pathname, op_mask);
    int   ret           = real_mkfifoat(dirfd, reworked_path, mode);

    LDFL_LOG_ERR(ret == 0, "real_mkfifoat failed: dirfd=%d, pathname=%s, mode=%d, errno=%d (%s)", dirfd, reworked_path,
                 mode, errno, strerror(errno));

    free(reworked_path);
    return ret;
}

int mknodat(int dirfd, const char *pathname, mode_t mode, dev_t dev) {
    RINIT;
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_RO | LDFL_OP_PERM | LDFL_OP_DENY;

    LDFL_LOG_CALL("mknodat called: dirfd=%d, pathname=%s, mode=%o, dev=%lu", dirfd, pathname, mode, (unsigned long)dev);

    char *reworked_path = apply_rules_and_cleanup("mknodat", pathname, op_mask);
    int   ret           = real_mknodat(dirfd, reworked_path, mode, dev);

    LDFL_LOG_ERR(ret == 0, "real_mknodat failed: dirfd=%d, pathname=%s, mode=%d, dev=%ld, errno=%d (%s)", dirfd,
                 reworked_path, mode, dev, errno, strerror(errno));

    free(reworked_path);
    return ret;
}

int mknod(const char *pathname, mode_t mode, dev_t dev) {
    RINIT;
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_RO | LDFL_OP_PERM | LDFL_OP_DENY;

    LDFL_LOG_CALL("mknod called: pathname=%s, mode=%o, dev=%lu", pathname, mode, (unsigned long)dev);

    char *reworked_path = apply_rules_and_cleanup("mknod", pathname, op_mask);
    int   ret           = real_mknod(reworked_path, mode, dev);

    LDFL_LOG_ERR(ret == 0, "real_mknod failed: pathname=%s, mode=%d, dev=%ld, errno=%d (%s)", reworked_path, mode, dev,
                 errno, strerror(errno));

    free(reworked_path);
    return ret;
}

int statx(int dirfd, const char *restrict pathname, int flags, unsigned int mask, struct statx *restrict statxbuf) {
    RINIT;
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_RO | LDFL_OP_PERM | LDFL_OP_DENY;

    LDFL_LOG_CALL("statx called: dirfd=%d, pathname=%s, flags=%d, mask=%u", dirfd, pathname, flags, mask);

    char *reworked_path = apply_rules_and_cleanup("statx", pathname, op_mask);
    int   ret           = real_statx(dirfd, reworked_path, flags, mask, statxbuf);

    LDFL_LOG_ERR(ret == 0, "real_statx failed: dirfd=%d, pathname=%s, flags=%d, mask=%d, errno=%d (%s)", dirfd,
                 reworked_path, flags, mask, errno, strerror(errno));

    free(reworked_path);
    return ret;
}

int creat(const char *pathname, mode_t mode) {
    RINIT;
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_RO | LDFL_OP_PERM | LDFL_OP_DENY;

    LDFL_LOG_CALL("creat called: pathname=%s, mode=%o", pathname, mode);

    char *reworked_path = apply_rules_and_cleanup("creat", pathname, op_mask);
    int   ret           = real_creat(reworked_path, mode);

    LDFL_LOG_ERR(ret == 0, "real_creat failed: pathname=%s, mode=%d, errno=%d (%s)", reworked_path, mode, errno,
                 strerror(errno));

    free(reworked_path);
    return ret;
}

#if defined(__APPLE__)
int renamex_np(const char *oldpath, const char *newpath, int flags) {
    RINIT;
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_RO | LDFL_OP_PERM | LDFL_OP_DENY;

    LDFL_LOG_CALL("renamex_np called: oldpath=%s, newpath=%s, flags=%d", oldpath, newpath, flags);

    char *reworked_oldpath = apply_rules_and_cleanup("renamex_np", oldpath, op_mask);
    char *reworked_newpath = apply_rules_and_cleanup("renamex_np", newpath, op_mask);
    int   ret              = real_renamex_np(reworked_oldpath, reworked_newpath, flags);

    LDFL_LOG_ERR(ret == 0, "real_renamex_np failed: oldpath=%s, newpath=%s, flags=%d, errno=%d (%s)", reworked_oldpath,
                 reworked_newpath, flags, errno, strerror(errno));

    free(reworked_oldpath);
    free(reworked_newpath);
    return ret;
}

int renameatx_np(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags) {
    RINIT;
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_RO | LDFL_OP_PERM | LDFL_OP_DENY;

    LDFL_LOG_CALL("renameatx_np called: olddirfd=%d, oldpath=%s, newdirfd=%d, newpath=%s, flags=%d", olddirfd, oldpath,
                  newdirfd, newpath, flags);

    char *reworked_oldpath = apply_rules_and_cleanup("renamexat_np", oldpath, op_mask);
    char *reworked_newpath = apply_rules_and_cleanup("renamexat_np", newpath, op_mask);
    int   ret              = real_renameatx_np(olddirfd, reworked_oldpath, newdirfd, reworked_newpath, flags);

    LDFL_LOG_ERR(ret == 0,
                 "real_renameatx_np failed: olddirfd=%d, oldpath=%s, newdirfd=%d, newpath=%s, "
                 "flags=%d, errno=%d (%s)",
                 olddirfd, reworked_oldpath, newdirfd, reworked_newpath, flags, errno, strerror(errno));

    free(reworked_oldpath);
    free(reworked_newpath);
    return ret;
}
#endif

#endif
/** @endcond */
