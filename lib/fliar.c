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
 * @brief Structures of interest in fliar.c
 */

/**
 * @enum ldfl_log_category_t
 * @brief Bitmask flags for specifying logging categories.
 *
 * This enumeration defines flags used to control the logging behavior
 * of the ld-fliar. Each flag represents a specific category of operations
 * to be logged, and they can be combined using bitwise OR operations.
 */
typedef enum {
    LDFL_LOG_FN_CALL        = 1ULL << 0, /**< Log LibC function calls. */
    LDFL_LOG_MAPPING_SEARCH = 1ULL << 1, /**< Log mapping search operations. */
    LDFL_LOG_MAPPING_APPLY  = 1ULL << 2, /**< Log mapping application operations. */
    LDFL_LOG_INIT           = 1ULL << 3, /**< Log initialization and deinitialization operations. */
    LDFL_LOG_ALL            = ~0ULL      /**< Log all categories. */
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
 * @example
 * ldfl_mapping_t mappings[] = {
 *     {"mapping1", "pattern1", LDFL_OP_MAP,  "target1",  NULL},
 *     {"mapping2", "pattern2", LDFL_OP_PERM, "target2", "kakwa:kakwa|0700|0600"},
 *     {NULL, NULL, LDFL_OP_END, NULL, NULL}  // Terminating entry
 * };
 */
typedef struct {
    const char      *name;           /**< Name of the mapping rule. Only informational */
    const char      *search_pattern; /**< Matching regex on file/dir path. set to NULL to chain */
    ldfl_operation_t operation;      /**< Operation type. */
    const void      *target;         /**< Replacement regex for the file/dir path. */
    const char      *extra_options;  /**< Extra options options. */
} ldfl_mapping_t;

/**
 * @brief Variadic logger function type.
 *
 * This function type is used for logging messages in fliar.
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

// Wrapper struct to store compiled regex
typedef struct {
    const ldfl_mapping_t *mapping;        // Pointer to the original mapping
    pcre2_code           *matching_regex; // Compiled matching regex
} compiled_mapping_t;

// Example default blob data
static const unsigned char ldf_default_blob[] = "hello from ld-fliar";

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

// Syslog logger
void ldfl_syslog_logger(uint64_t mask, int priority, const char *fmt, ...) {
    if (priority > ldfl_setting.log_level)
        return;
    if (!(mask & ldfl_setting.log_mask))
        return;

    va_list args;
    va_start(args, fmt);
    openlog(NULL, LOG_PID, LOG_USER);
    vsyslog(priority, fmt, args);
    closelog();
    va_end(args);
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

// TODO remove
#define FLIAR_STATIC_CONFIG

#ifdef FLIAR_STATIC_CONFIG
// TODO fix pathname
#include "../cfg/ldfl-config.h"
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

bool ldfl_find_matching_rules(const char *call, const char *pathname, uint64_t mask, compiled_mapping_t **return_rules,
                              int *num_rules, pcre2_match_data **return_pcre_match) {
    if (pathname == NULL) {
        return false;
    }
    for (int i = 0; i < ldfl_rule_count; i++) {
        // Rule not matching
        if (!(ldfl_compiled_rules[i].mapping->operation & mask) || (ldfl_compiled_rules[i].matching_regex == NULL)) {
            ldfl_setting.logger(LDFL_LOG_MAPPING_SEARCH, LOG_DEBUG, "rule[%s] not relevant for call '%s', skipping",
                                ldfl_mapping[i].name, call);
            continue;
        }

        pcre2_match_data *match_data =
            pcre2_match_data_create_from_pattern(ldfl_compiled_rules[i].matching_regex, NULL);

        int rc = pcre2_match(ldfl_compiled_rules[i].matching_regex, // The compiled pattern
                             (PCRE2_SPTR)pathname,                  // The subject string
                             strlen(pathname),                      // Length of the subject
                             0,                                     // Start at offset 0
                             0,                                     // Default options
                             match_data,                            // Match data structure
                             NULL                                   // Default match context
        );
        if (rc <= 0) {
            ldfl_setting.logger(LDFL_LOG_MAPPING_SEARCH, LOG_DEBUG, "rule[%s] not matching pathname '%s' for call '%s'",
                                ldfl_mapping[i].name, pathname, call);
            pcre2_match_data_free(match_data);
            continue;
        }
        int matching_rule_count = 1;
        for (int j = i + 1; j < ldfl_rule_count; j++) {
            if (ldfl_compiled_rules[j].matching_regex != NULL) {
                break;
            }
            matching_rule_count++;
        }
        *return_rules = calloc(sizeof(compiled_mapping_t *), matching_rule_count + 1);

        for (int j = 0; j < matching_rule_count; j++) {
            (*return_rules)[j] = ldfl_compiled_rules[j + i];
            ldfl_setting.logger(LDFL_LOG_MAPPING_SEARCH, LOG_INFO,
                                "rule[%s] match pathname '%s', selected for call '%s'", ldfl_mapping[i].name, pathname,
                                call);
        }
        *num_rules         = matching_rule_count;
        *return_pcre_match = match_data;
        return true;
    }
    return false;
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

void ldfl_apply_rules(compiled_mapping_t *mapping_rules, int num_rules, pcre2_match_data *match_group,
                      const char *pathname_in, char **pathname_out) {
    if (pathname_in == NULL) {
        *pathname_out = calloc(sizeof(char), 1);
        return;
    }
    if (num_rules <= 0) {
        ldfl_setting.logger(LDFL_LOG_MAPPING_APPLY, LOG_DEBUG, "No Rule to apply on path '%s', returning the same path",
                            pathname_in);

        *pathname_out = calloc(sizeof(char), strlen(pathname_in) + 1);
        stpcpy(*pathname_out, pathname_in);
        return;
    }
    for (int i = 0; i < num_rules; i++) {
        switch (mapping_rules[i].mapping->operation) {
        case LDFL_OP_NOOP:
            *pathname_out = calloc(sizeof(char), strlen(pathname_in) + 1);
            stpcpy(*pathname_out, pathname_in);
            return; // FIXME (don't only apply the first rule)
            break;
        case LDFL_OP_MAP:
            // Extract the target replacement pattern.
            char      *new_pathname    = calloc(sizeof(char), PATH_MAX);
            PCRE2_SIZE replacement_len = PATH_MAX;

            // Perform the substitution and store the result.
            pcre2_substitute(mapping_rules[i].matching_regex, (PCRE2_SPTR)pathname_in, PCRE2_ZERO_TERMINATED, 0,
                             PCRE2_SUBSTITUTE_GLOBAL, match_group, NULL, (PCRE2_SPTR)mapping_rules[i].mapping->target,
                             PCRE2_ZERO_TERMINATED, (PCRE2_UCHAR *)new_pathname, &replacement_len);
            if (replacement_len <= 0) {
                ldfl_setting.logger(LDFL_LOG_MAPPING_APPLY, LOG_WARNING,
                                    "Replacement in path failed for rule '%s' on path '%s'",
                                    mapping_rules[i].mapping->name, pathname_in);
            }
            *pathname_out = new_pathname;

            ldfl_setting.logger(LDFL_LOG_MAPPING_APPLY, LOG_DEBUG,
                                "LDFL_OP_MAP Rule [%s] applied, path '%s' rewritten to '%s'",
                                mapping_rules[i].mapping->name, pathname_in, *pathname_out);
            return; // FIXME (don't only apply the first rule)
            break;
        case LDFL_OP_EXEC_MAP:
            ldfl_setting.logger(LDFL_LOG_MAPPING_APPLY, LOG_WARNING, "Operation LDFL_OP_EXEC_MAP not yet handle");
            *pathname_out = calloc(sizeof(char), strlen(pathname_in) + 1);
            stpcpy(*pathname_out, pathname_in);
            return; // FIXME (don't only apply the first rule)
            break;
        case LDFL_OP_MEM_OPEN:
            *pathname_out = calloc(sizeof(char), strlen(pathname_in) + 1);
            stpcpy(*pathname_out, pathname_in);
            ldfl_setting.logger(LDFL_LOG_MAPPING_APPLY, LOG_WARNING, "Operation LDFL_OP_MEM_OPEN not yet handle");
            return; // FIXME (don't only apply the first rule)
            break;
        case LDFL_OP_STATIC:
            *pathname_out = calloc(sizeof(char), strlen(pathname_in) + 1);
            stpcpy(*pathname_out, pathname_in);
            ldfl_setting.logger(LDFL_LOG_MAPPING_APPLY, LOG_WARNING, "Operation LDFL_OP_STATIC not yet handle");
            return; // FIXME (don't only apply the first rule)
            break;
        case LDFL_OP_PERM:
            *pathname_out = calloc(sizeof(char), strlen(pathname_in) + 1);
            stpcpy(*pathname_out, pathname_in);
            ldfl_setting.logger(LDFL_LOG_MAPPING_APPLY, LOG_WARNING, "Operation LDFL_OP_PERM not yet handle");
            return; // FIXME (don't only apply the first rule)
            break;
        case LDFL_OP_DENY:
            *pathname_out = calloc(sizeof(char), strlen(pathname_in) + 1);
            stpcpy(*pathname_out, pathname_in);
            ldfl_setting.logger(LDFL_LOG_MAPPING_APPLY, LOG_WARNING, "Operation LDFL_OP_DENY not yet handle");
            return; // FIXME (don't only apply the first rule)
            break;
        default:
            *pathname_out = calloc(sizeof(char), strlen(pathname_in) + 1);
            stpcpy(*pathname_out, pathname_in);
            ldfl_setting.logger(LDFL_LOG_MAPPING_APPLY, LOG_WARNING, "Unknown operation %d not yet handle",
                                mapping_rules[i].mapping->operation);
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
    if (!ldfl_is_init) {                                                                                               \
        ldfl_setting.logger(LDFL_LOG_INIT, LOG_DEBUG, "ld-fliar init did not run, re-init");                           \
        ldfl_init();                                                                                                   \
    };

// Flag to check if ldfl is properly initialized
// FIXME concurrency issue, add some locking when doing the init
bool ldfl_is_init;

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
    ldfl_setting.logger(LDFL_LOG_INIT, LOG_DEBUG, "ld-fliar init called");
    ldfl_regex_init();

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
    ldfl_is_init = true;
    ldfl_setting.logger(LDFL_LOG_INIT, LOG_DEBUG, "initialized");
}

// de-init function
// free compiled regexp
static void __attribute__((destructor(101))) ldfl_dinit() {
    ldfl_setting.logger(LDFL_LOG_INIT, LOG_DEBUG, "ld-fliar dinit called");
    ldfl_regex_free();
    ldfl_setting.logger(LDFL_LOG_INIT, LOG_DEBUG, "freed");
}

FILE *fopen(const char *restrict pathname, const char *restrict mode) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "fopen called: pathname=%s, mode=%s", pathname, mode);
    RINIT;
    char               *reworked_path = NULL;
    compiled_mapping_t *return_rules;
    pcre2_match_data   *return_pcre_match = NULL;
    int                 num_rules         = 0;
    ldfl_find_matching_rules("fopen", pathname, op_mask, &return_rules, &num_rules, &return_pcre_match);
    ldfl_apply_rules(return_rules, num_rules, return_pcre_match, pathname, &reworked_path);
    pcre2_match_data_free(return_pcre_match);
    if (num_rules > 0) {
        free(return_rules);
    };

    FILE *ret = real_fopen(reworked_path, mode);
    free(reworked_path);
    return ret;
}

FILE *fopen64(const char *pathname, const char *mode) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "fopen64 called: pathname=%s, mode=%s", pathname, mode);
    RINIT;
    char               *reworked_path = NULL;
    compiled_mapping_t *return_rules;
    pcre2_match_data   *return_pcre_match = NULL;
    int                 num_rules         = 0;
    ldfl_find_matching_rules("fopen64", pathname, op_mask, &return_rules, &num_rules, &return_pcre_match);
    ldfl_apply_rules(return_rules, num_rules, return_pcre_match, pathname, &reworked_path);
    pcre2_match_data_free(return_pcre_match);
    if (num_rules > 0) {
        free(return_rules);
    };

    FILE *ret = real_fopen64(reworked_path, mode);
    free(reworked_path);
    return ret;
}

int openat(int dirfd, const char *pathname, int flags, ...) {
    va_list args;
    va_start(args, flags);

    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    // FIXME handle variadic properly
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "openat called: dirfd=%d, pathname=%s, flags=%d, mode=%o", dirfd,
                        pathname, flags, va_arg(args, mode_t));
    RINIT;
    char               *reworked_path = NULL;
    compiled_mapping_t *return_rules;
    pcre2_match_data   *return_pcre_match = NULL;
    int                 num_rules         = 0;
    ldfl_find_matching_rules("openat", pathname, op_mask, &return_rules, &num_rules, &return_pcre_match);
    ldfl_apply_rules(return_rules, num_rules, return_pcre_match, pathname, &reworked_path);
    pcre2_match_data_free(return_pcre_match);
    if (num_rules > 0) {
        free(return_rules);
    };
    va_end(args);
    int ret = ldfl_variadic_mode_wrap(real_openat, dirfd, reworked_path, flags);
    free(reworked_path);
    return ret;
}

int open(const char *pathname, int flags, ... /* mode_t mode */) {
    va_list args;
    va_start(args, flags);

    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    // FIXME handle variadic properly
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "open called: pathname=%s, flags=%d, mode=%o", pathname, flags,
                        va_arg(args, mode_t));
    RINIT;
    char               *reworked_path = NULL;
    compiled_mapping_t *return_rules;
    pcre2_match_data   *return_pcre_match = NULL;
    int                 num_rules         = 0;
    ldfl_find_matching_rules("open", pathname, op_mask, &return_rules, &num_rules, &return_pcre_match);
    ldfl_apply_rules(return_rules, num_rules, return_pcre_match, pathname, &reworked_path);
    pcre2_match_data_free(return_pcre_match);
    if (num_rules > 0) {
        free(return_rules);
    };

    va_end(args);
    int ret = ldfl_variadic_mode_wrap(real_open, reworked_path, flags);
    free(reworked_path);
    return ret;
}

int open64(const char *pathname, int flags, ... /* mode_t mode */) {
    va_list args;
    va_start(args, flags);

    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    // FIXME handle variadic properly
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "open64 called: pathname=%s, flags=%d, mode=%o", pathname, flags,
                        va_arg(args, mode_t));
    RINIT;
    char               *reworked_path = NULL;
    compiled_mapping_t *return_rules;
    pcre2_match_data   *return_pcre_match = NULL;
    int                 num_rules         = 0;
    ldfl_find_matching_rules("open64", pathname, op_mask, &return_rules, &num_rules, &return_pcre_match);
    ldfl_apply_rules(return_rules, num_rules, return_pcre_match, pathname, &reworked_path);
    pcre2_match_data_free(return_pcre_match);
    if (num_rules > 0) {
        free(return_rules);
    };

    va_end(args);
    int ret = ldfl_variadic_mode_wrap(real_open64, reworked_path, flags);
    free(reworked_path);
    return ret;
}

int openat64(int dirfd, const char *pathname, int flags, ... /* mode_t mode */) {
    va_list args;
    va_start(args, flags);

    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    // FIXME handle variadic properly
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "openat64 called: dirfd=%d, pathname=%s, flags=%d, mode=%o", dirfd,
                        pathname, flags, va_arg(args, mode_t));
    RINIT;
    char               *reworked_path = NULL;
    compiled_mapping_t *return_rules;
    pcre2_match_data   *return_pcre_match = NULL;
    int                 num_rules         = 0;
    ldfl_find_matching_rules("openat64", pathname, op_mask, &return_rules, &num_rules, &return_pcre_match);
    ldfl_apply_rules(return_rules, num_rules, return_pcre_match, pathname, &reworked_path);
    pcre2_match_data_free(return_pcre_match);
    if (num_rules > 0) {
        free(return_rules);
    };

    va_end(args);
    int ret = ldfl_variadic_mode_wrap(real_openat64, dirfd, reworked_path, flags);
    free(reworked_path);
    return ret;
}

int rename(const char *oldpath, const char *newpath) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "rename called: oldpath=%s, newpath=%s", oldpath, newpath);
    RINIT;
    char               *reworked_path = NULL;
    compiled_mapping_t *return_rules;
    pcre2_match_data   *return_pcre_match = NULL;
    int                 num_rules         = 0;
    ldfl_find_matching_rules("rename", oldpath, op_mask, &return_rules, &num_rules, &return_pcre_match);
    ldfl_apply_rules(return_rules, num_rules, return_pcre_match, oldpath, &reworked_path);
    pcre2_match_data_free(return_pcre_match);
    if (num_rules > 0) {
        free(return_rules);
    };
    // TODO newpath
    int ret = real_rename(reworked_path, newpath);
    free(reworked_path);
    return ret;
}

int renameat2(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    REAL(renameat2);
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG,
                        "renameat2 called: olddirfd=%d, oldpath=%s, newdirfd=%d, newpath=%s, flags=%u", olddirfd,
                        oldpath, newdirfd, newpath, flags);
    RINIT;
    char               *reworked_path = NULL;
    compiled_mapping_t *return_rules;
    pcre2_match_data   *return_pcre_match = NULL;
    int                 num_rules         = 0;
    ldfl_find_matching_rules("olddirfd", oldpath, op_mask, &return_rules, &num_rules, &return_pcre_match);
    ldfl_apply_rules(return_rules, num_rules, return_pcre_match, oldpath, &reworked_path);
    pcre2_match_data_free(return_pcre_match);
    if (num_rules > 0) {
        free(return_rules);
    };
    // TODO newpath

    int ret = real_renameat2(olddirfd, reworked_path, newdirfd, newpath, flags);
    free(reworked_path);
    return ret;
}

int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG,
                        "renameat called: olddirfd=%d, oldpath=%s, newdirfd=%d, newpath=%s", olddirfd, oldpath,
                        newdirfd, newpath);
    RINIT;
    char               *reworked_path = NULL;
    compiled_mapping_t *return_rules;
    pcre2_match_data   *return_pcre_match = NULL;
    int                 num_rules         = 0;
    ldfl_find_matching_rules("renameat", oldpath, op_mask, &return_rules, &num_rules, &return_pcre_match);
    ldfl_apply_rules(return_rules, num_rules, return_pcre_match, oldpath, &reworked_path);
    pcre2_match_data_free(return_pcre_match);
    if (num_rules > 0) {
        free(return_rules);
    };
    // TODO newpath

    int ret = real_renameat(olddirfd, reworked_path, newdirfd, newpath);
    free(reworked_path);
    return ret;
}

int unlink(const char *pathname) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "unlink called: pathname=%s", pathname);
    RINIT;
    char               *reworked_path = NULL;
    compiled_mapping_t *return_rules;
    pcre2_match_data   *return_pcre_match = NULL;
    int                 num_rules         = 0;
    ldfl_find_matching_rules("unlink", pathname, op_mask, &return_rules, &num_rules, &return_pcre_match);
    ldfl_apply_rules(return_rules, num_rules, return_pcre_match, pathname, &reworked_path);
    pcre2_match_data_free(return_pcre_match);
    if (num_rules > 0) {
        free(return_rules);
    };

    int ret = real_unlink(reworked_path);
    free(reworked_path);
    return ret;
}

int unlinkat(int dirfd, const char *pathname, int flags) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "unlinkat called: dirfd=%d, pathname=%s, flags=%d", dirfd,
                        pathname, flags);
    RINIT;
    char               *reworked_path = NULL;
    compiled_mapping_t *return_rules;
    pcre2_match_data   *return_pcre_match = NULL;
    int                 num_rules         = 0;
    ldfl_find_matching_rules("unlinkat", pathname, op_mask, &return_rules, &num_rules, &return_pcre_match);
    ldfl_apply_rules(return_rules, num_rules, return_pcre_match, pathname, &reworked_path);
    pcre2_match_data_free(return_pcre_match);
    if (num_rules > 0) {
        free(return_rules);
    };

    int ret = real_unlinkat(dirfd, reworked_path, flags);
    free(reworked_path);
    return ret;
}

int utime(const char *pathname, const struct utimbuf *times) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "utimes called: pathname=%s, times=[%ld, %ld]", pathname,
                        (times == NULL) ? 0 : times->actime, (times == NULL) ? 0 : times->modtime);
    RINIT;
    char               *reworked_path = NULL;
    compiled_mapping_t *return_rules;
    pcre2_match_data   *return_pcre_match = NULL;
    int                 num_rules         = 0;
    ldfl_find_matching_rules("utime", pathname, op_mask, &return_rules, &num_rules, &return_pcre_match);
    ldfl_apply_rules(return_rules, num_rules, return_pcre_match, pathname, &reworked_path);
    pcre2_match_data_free(return_pcre_match);
    if (num_rules > 0) {
        free(return_rules);
    };

    int ret = real_utime(reworked_path, times);
    free(reworked_path);
    return ret;
}

int utimes(const char *pathname, const struct timeval times[2]) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "utimes called: pathname=%s, times=[%ld:%ld, %ld:%ld]", pathname,
                        (times == NULL) ? 0 : times[0].tv_sec, (times == NULL) ? 0 : times[0].tv_usec,
                        (times == NULL) ? 0 : times[1].tv_sec, (times == NULL) ? 0 : times[1].tv_usec);
    RINIT;
    char               *reworked_path = NULL;
    compiled_mapping_t *return_rules;
    pcre2_match_data   *return_pcre_match = NULL;
    int                 num_rules         = 0;
    ldfl_find_matching_rules("utimes", pathname, op_mask, &return_rules, &num_rules, &return_pcre_match);
    ldfl_apply_rules(return_rules, num_rules, return_pcre_match, pathname, &reworked_path);
    pcre2_match_data_free(return_pcre_match);
    if (num_rules > 0) {
        free(return_rules);
    };

    int ret = real_utimes(reworked_path, times);
    free(reworked_path);
    return ret;
}

int access(const char *pathname, int mode) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "access called: pathname=%s, mode=%d", pathname, mode);
    RINIT;
    char               *reworked_path = NULL;
    compiled_mapping_t *return_rules;
    pcre2_match_data   *return_pcre_match = NULL;
    int                 num_rules         = 0;
    ldfl_find_matching_rules("access", pathname, op_mask, &return_rules, &num_rules, &return_pcre_match);
    ldfl_apply_rules(return_rules, num_rules, return_pcre_match, pathname, &reworked_path);
    pcre2_match_data_free(return_pcre_match);
    if (num_rules > 0) {
        free(return_rules);
    };

    int ret = real_access(reworked_path, mode);
    free(reworked_path);
    return ret;
}

int fstatat(int dirfd, const char *pathname, struct stat *statbuf, int flags) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "fstatat called: dirfd=%d, pathname=%s, flags=%d", dirfd, pathname,
                        flags);
    RINIT;
    char               *reworked_path = NULL;
    compiled_mapping_t *return_rules;
    pcre2_match_data   *return_pcre_match = NULL;
    int                 num_rules         = 0;
    ldfl_find_matching_rules("fstatat", pathname, op_mask, &return_rules, &num_rules, &return_pcre_match);
    ldfl_apply_rules(return_rules, num_rules, return_pcre_match, pathname, &reworked_path);
    pcre2_match_data_free(return_pcre_match);
    if (num_rules > 0) {
        free(return_rules);
    };

    int ret = real_fstatat(dirfd, pathname, statbuf, flags);
    free(reworked_path);
    return ret;
}

int __xstat(int version, const char *pathname, struct stat *statbuf) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "__xstat called: version=%d, pathname=%s", version, pathname);
    RINIT;
    char               *reworked_path = NULL;
    compiled_mapping_t *return_rules;
    pcre2_match_data   *return_pcre_match = NULL;
    int                 num_rules         = 0;
    ldfl_find_matching_rules("__xstat", pathname, op_mask, &return_rules, &num_rules, &return_pcre_match);
    ldfl_apply_rules(return_rules, num_rules, return_pcre_match, pathname, &reworked_path);
    pcre2_match_data_free(return_pcre_match);
    if (num_rules > 0) {
        free(return_rules);
    };

    int ret = real___xstat(version, pathname, statbuf);
    free(reworked_path);
    return ret;
}

int __xstat64(int version, const char *pathname, struct stat *statbuf) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "__xstat64 called: version=%d, pathname=%s", version, pathname);
    RINIT;
    char               *reworked_path = NULL;
    compiled_mapping_t *return_rules;
    pcre2_match_data   *return_pcre_match = NULL;
    int                 num_rules         = 0;
    ldfl_find_matching_rules("__xstat64", pathname, op_mask, &return_rules, &num_rules, &return_pcre_match);
    ldfl_apply_rules(return_rules, num_rules, return_pcre_match, pathname, &reworked_path);
    pcre2_match_data_free(return_pcre_match);
    if (num_rules > 0) {
        free(return_rules);
    };

    int ret = real___xstat64(version, pathname, statbuf);
    free(reworked_path);
    return ret;
}

int __lxstat(int version, const char *pathname, struct stat *statbuf) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "__lxstat called: version=%d, pathname=%s", version, pathname);
    RINIT;
    char               *reworked_path = NULL;
    compiled_mapping_t *return_rules;
    pcre2_match_data   *return_pcre_match = NULL;
    int                 num_rules         = 0;
    ldfl_find_matching_rules("__lxstat", pathname, op_mask, &return_rules, &num_rules, &return_pcre_match);
    ldfl_apply_rules(return_rules, num_rules, return_pcre_match, pathname, &reworked_path);
    pcre2_match_data_free(return_pcre_match);
    if (num_rules > 0) {
        free(return_rules);
    };

    int ret = real___lxstat(version, pathname, statbuf);
    free(reworked_path);
    return ret;
}

int __fxstatat(int version, int dirfd, const char *pathname, struct stat *statbuf, int flags) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "__fxstatat called: version=%d, dirfd=%d, pathname=%s, flags=%d",
                        version, dirfd, pathname, flags);
    RINIT;
    char               *reworked_path = NULL;
    compiled_mapping_t *return_rules;
    pcre2_match_data   *return_pcre_match = NULL;
    int                 num_rules         = 0;
    ldfl_find_matching_rules("__fxstatat", pathname, op_mask, &return_rules, &num_rules, &return_pcre_match);
    ldfl_apply_rules(return_rules, num_rules, return_pcre_match, pathname, &reworked_path);
    pcre2_match_data_free(return_pcre_match);
    if (num_rules > 0) {
        free(return_rules);
    };

    int ret = real___fxstatat(version, dirfd, pathname, statbuf, flags);
    free(reworked_path);
    return ret;
}

int utimensat(int dirfd, const char *pathname, const struct timespec times[2], int flags) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG,
                        "utimensat called: dirfd=%d, pathname=%s, times=[%ld, %ld], flags=%d", dirfd, pathname,
                        (times == NULL) ? 0 : times[0].tv_sec, (times == NULL) ? 0 : times[1].tv_sec, flags);
    RINIT;
    char               *reworked_path = NULL;
    compiled_mapping_t *return_rules;
    pcre2_match_data   *return_pcre_match = NULL;
    int                 num_rules         = 0;
    ldfl_find_matching_rules("utimensat", pathname, op_mask, &return_rules, &num_rules, &return_pcre_match);
    ldfl_apply_rules(return_rules, num_rules, return_pcre_match, pathname, &reworked_path);
    pcre2_match_data_free(return_pcre_match);
    if (num_rules > 0) {
        free(return_rules);
    };

    int ret = real_utimensat(dirfd, pathname, times, flags);
    free(reworked_path);
    return ret;
}

int execve(const char *pathname, char *const argv[], char *const envp[]) {
    uint64_t op_mask  = LDFL_OP_NOOP | LDFL_OP_EXEC_MAP | LDFL_OP_DENY;
    char    *argv_str = ldfl_render_nullable_array(argv);
    char    *envp_str = ldfl_render_nullable_array(envp);
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "execve called: pathname=%s, argv=%s, envp=%s", pathname, argv_str,
                        envp_str);
    free(argv_str);
    free(envp_str);
    RINIT;
    char               *reworked_path = NULL;
    compiled_mapping_t *return_rules;
    pcre2_match_data   *return_pcre_match = NULL;
    int                 num_rules         = 0;
    ldfl_find_matching_rules("execve", pathname, op_mask, &return_rules, &num_rules, &return_pcre_match);
    ldfl_apply_rules(return_rules, num_rules, return_pcre_match, pathname, &reworked_path);
    pcre2_match_data_free(return_pcre_match);
    if (num_rules > 0) {
        free(return_rules);
    };
    // TODO argv[0]

    int ret = real_execve(pathname, argv, envp);
    free(reworked_path);
    return ret;
}

int execl(const char *pathname, const char *arg, ...) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_EXEC_MAP | LDFL_OP_DENY;
    va_list  args;
    va_start(args, arg);
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "execl called: pathname=%s, arg=%s", pathname, arg);
    RINIT;
    char               *reworked_path = NULL;
    compiled_mapping_t *return_rules;
    pcre2_match_data   *return_pcre_match = NULL;
    int                 num_rules         = 0;
    ldfl_find_matching_rules("execl", pathname, op_mask, &return_rules, &num_rules, &return_pcre_match);
    ldfl_apply_rules(return_rules, num_rules, return_pcre_match, pathname, &reworked_path);
    pcre2_match_data_free(return_pcre_match);
    if (num_rules > 0) {
        free(return_rules);
    };
    // TODO argv[0]

    va_end(args);
    int ret = ldfl_variadic_str_wrap(real_execl, arg, reworked_path, arg);
    free(reworked_path);
    return ret;
}

int execlp(const char *file, const char *arg, ...) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_EXEC_MAP | LDFL_OP_DENY;
    va_list  args;
    va_start(args, arg);
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "execlp called: file=%s, arg=%s", file, arg);
    va_end(args);
    RINIT;
    char               *reworked_path = NULL;
    compiled_mapping_t *return_rules;
    pcre2_match_data   *return_pcre_match = NULL;
    int                 num_rules         = 0;
    ldfl_find_matching_rules("execlp", file, op_mask, &return_rules, &num_rules, &return_pcre_match);
    ldfl_apply_rules(return_rules, num_rules, return_pcre_match, file, &reworked_path);
    pcre2_match_data_free(return_pcre_match);
    if (num_rules > 0) {
        free(return_rules);
    };
    // TODO argv[0]

    int ret = ldfl_variadic_str_wrap(real_execlp, arg, reworked_path, arg);
    free(reworked_path);
    return ret;
}

int execv(const char *pathname, char *const argv[]) {
    uint64_t op_mask  = LDFL_OP_NOOP | LDFL_OP_EXEC_MAP | LDFL_OP_DENY;
    char    *argv_str = ldfl_render_nullable_array(argv);
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "execv called: pathname=%s, argv=%s", pathname, argv_str);
    free(argv_str);
    RINIT;
    char               *reworked_path = NULL;
    compiled_mapping_t *return_rules;
    pcre2_match_data   *return_pcre_match = NULL;
    int                 num_rules         = 0;
    ldfl_find_matching_rules("execv", pathname, op_mask, &return_rules, &num_rules, &return_pcre_match);
    ldfl_apply_rules(return_rules, num_rules, return_pcre_match, pathname, &reworked_path);
    pcre2_match_data_free(return_pcre_match);
    if (num_rules > 0) {
        free(return_rules);
    };
    // TODO argv[0]

    int ret = real_execv(pathname, argv);
    free(reworked_path);
    return ret;
}

int execvp(const char *file, char *const argv[]) {
    uint64_t op_mask  = LDFL_OP_NOOP | LDFL_OP_EXEC_MAP | LDFL_OP_DENY;
    char    *argv_str = ldfl_render_nullable_array(argv);
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "execvp called: file=%s, argv=%s", file, argv_str);
    free(argv_str);
    RINIT;
    char               *reworked_path = NULL;
    compiled_mapping_t *return_rules;
    pcre2_match_data   *return_pcre_match = NULL;
    int                 num_rules         = 0;
    ldfl_find_matching_rules("execvp", file, op_mask, &return_rules, &num_rules, &return_pcre_match);
    ldfl_apply_rules(return_rules, num_rules, return_pcre_match, file, &reworked_path);
    pcre2_match_data_free(return_pcre_match);
    if (num_rules > 0) {
        free(return_rules);
    };
    // TODO argv[0]

    int ret = real_execvp(reworked_path, argv);
    free(reworked_path);
    return ret;
}

DIR *opendir(const char *name) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "opendir called: name=%s", name);
    RINIT;
    char               *reworked_path = NULL;
    compiled_mapping_t *return_rules;
    pcre2_match_data   *return_pcre_match = NULL;
    int                 num_rules         = 0;
    ldfl_find_matching_rules("opendir", name, op_mask, &return_rules, &num_rules, &return_pcre_match);
    ldfl_apply_rules(return_rules, num_rules, return_pcre_match, name, &reworked_path);
    pcre2_match_data_free(return_pcre_match);
    if (num_rules > 0) {
        free(return_rules);
    };

    DIR *ret = real_opendir(reworked_path);
    free(reworked_path);
    return ret;
}

int mkdir(const char *pathname, mode_t mode) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "mkdir called: pathname=%s, mode=%o", pathname, mode);
    RINIT;
    char               *reworked_path = NULL;
    compiled_mapping_t *return_rules;
    pcre2_match_data   *return_pcre_match = NULL;
    int                 num_rules         = 0;
    ldfl_find_matching_rules("mkdir", pathname, op_mask, &return_rules, &num_rules, &return_pcre_match);
    ldfl_apply_rules(return_rules, num_rules, return_pcre_match, pathname, &reworked_path);
    pcre2_match_data_free(return_pcre_match);
    if (num_rules > 0) {
        free(return_rules);
    };

    int ret = real_mkdir(reworked_path, mode);
    free(reworked_path);
    return ret;
}

int mkdirat(int dirfd, const char *pathname, mode_t mode) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "mkdirat called: dirfd=%d, pathname=%s, mode=%o", dirfd, pathname,
                        mode);
    RINIT;
    char               *reworked_path = NULL;
    compiled_mapping_t *return_rules;
    pcre2_match_data   *return_pcre_match = NULL;
    int                 num_rules         = 0;
    ldfl_find_matching_rules("mkdirat", pathname, op_mask, &return_rules, &num_rules, &return_pcre_match);
    ldfl_apply_rules(return_rules, num_rules, return_pcre_match, pathname, &reworked_path);
    pcre2_match_data_free(return_pcre_match);
    if (num_rules > 0) {
        free(return_rules);
    };

    int ret = real_mkdirat(dirfd, reworked_path, mode);
    free(reworked_path);
    return ret;
}

int rmdir(const char *pathname) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "rmdir called: pathname=%s", pathname);
    RINIT;
    char               *reworked_path = NULL;
    compiled_mapping_t *return_rules;
    pcre2_match_data   *return_pcre_match = NULL;
    int                 num_rules         = 0;
    ldfl_find_matching_rules("rmdir", pathname, op_mask, &return_rules, &num_rules, &return_pcre_match);
    ldfl_apply_rules(return_rules, num_rules, return_pcre_match, pathname, &reworked_path);
    pcre2_match_data_free(return_pcre_match);
    if (num_rules > 0) {
        free(return_rules);
    };

    int ret = real_rmdir(reworked_path);
    free(reworked_path);
    return ret;
}

int chdir(const char *pathname) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "chdir called: pathname=%s", pathname);
    RINIT;
    char               *reworked_path = NULL;
    compiled_mapping_t *return_rules;
    pcre2_match_data   *return_pcre_match = NULL;
    int                 num_rules         = 0;
    ldfl_find_matching_rules("chdir", pathname, op_mask, &return_rules, &num_rules, &return_pcre_match);
    ldfl_apply_rules(return_rules, num_rules, return_pcre_match, pathname, &reworked_path);
    pcre2_match_data_free(return_pcre_match);
    if (num_rules > 0) {
        free(return_rules);
    };

    int ret = real_chdir(reworked_path);
    free(reworked_path);
    return ret;
}

int symlink(const char *target, const char *linkpathname) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "symlink called: target=%s, linkpathname=%s", target,
                        linkpathname);
    RINIT;
    char               *reworked_path = NULL;
    compiled_mapping_t *return_rules;
    pcre2_match_data   *return_pcre_match = NULL;
    int                 num_rules         = 0;
    ldfl_find_matching_rules("symlink", linkpathname, op_mask, &return_rules, &num_rules, &return_pcre_match);
    ldfl_apply_rules(return_rules, num_rules, return_pcre_match, target, &reworked_path);
    pcre2_match_data_free(return_pcre_match);
    if (num_rules > 0) {
        free(return_rules);
    };
    // TODO target

    int ret = real_symlink(reworked_path, linkpathname);
    free(reworked_path);
    return ret;
}

ssize_t readlink(const char *pathname, char *buf, size_t bufsiz) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "readlink called: pathname=%s, bufsiz=%zu", pathname, bufsiz);
    RINIT;
    char               *reworked_path = NULL;
    compiled_mapping_t *return_rules;
    pcre2_match_data   *return_pcre_match = NULL;
    int                 num_rules         = 0;
    ldfl_find_matching_rules("readlink", pathname, op_mask, &return_rules, &num_rules, &return_pcre_match);
    ldfl_apply_rules(return_rules, num_rules, return_pcre_match, pathname, &reworked_path);
    pcre2_match_data_free(return_pcre_match);
    if (num_rules > 0) {
        free(return_rules);
    };

    int ret = real_readlink(reworked_path, buf, bufsiz);
    free(reworked_path);
    return ret;
}

int link(const char *oldpath, const char *newpath) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "link called: oldpath=%s, newpath=%s", oldpath, newpath);
    RINIT;
    char               *reworked_path = NULL;
    compiled_mapping_t *return_rules;
    pcre2_match_data   *return_pcre_match = NULL;
    int                 num_rules         = 0;
    ldfl_find_matching_rules("link", oldpath, op_mask, &return_rules, &num_rules, &return_pcre_match);
    ldfl_apply_rules(return_rules, num_rules, return_pcre_match, oldpath, &reworked_path);
    pcre2_match_data_free(return_pcre_match);
    if (num_rules > 0) {
        free(return_rules);
    };
    // TODO newpath

    int ret = real_link(reworked_path, newpath);
    free(reworked_path);
    return ret;
}

int linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG,
                        "linkat called: olddirfd=%d, oldpath=%s, newdirfd=%d, newpath=%s, flags=%d", olddirfd, oldpath,
                        newdirfd, newpath, flags);
    RINIT;
    char               *reworked_path = NULL;
    compiled_mapping_t *return_rules;
    pcre2_match_data   *return_pcre_match = NULL;
    int                 num_rules         = 0;
    ldfl_find_matching_rules("linkat", oldpath, op_mask, &return_rules, &num_rules, &return_pcre_match);
    ldfl_apply_rules(return_rules, num_rules, return_pcre_match, oldpath, &reworked_path);
    pcre2_match_data_free(return_pcre_match);
    if (num_rules > 0) {
        free(return_rules);
    };
    // TODO newpath

    int ret = real_linkat(olddirfd, reworked_path, newdirfd, newpath, flags);
    free(reworked_path);
    return ret;
}

int chmod(const char *pathname, mode_t mode) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "chmod called: pathname=%s, mode=%o", pathname, mode);
    RINIT;
    char               *reworked_path = NULL;
    compiled_mapping_t *return_rules;
    pcre2_match_data   *return_pcre_match = NULL;
    int                 num_rules         = 0;
    ldfl_find_matching_rules("chmod", pathname, op_mask, &return_rules, &num_rules, &return_pcre_match);
    ldfl_apply_rules(return_rules, num_rules, return_pcre_match, pathname, &reworked_path);
    pcre2_match_data_free(return_pcre_match);
    if (num_rules > 0) {
        free(return_rules);
    };

    int ret = real_chmod(reworked_path, mode);
    free(reworked_path);
    return ret;
}

int truncate(const char *pathname, off_t length) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "truncate called: pathname=%s, length=%ld", pathname, length);
    RINIT;
    char               *reworked_path = NULL;
    compiled_mapping_t *return_rules;
    pcre2_match_data   *return_pcre_match = NULL;
    int                 num_rules         = 0;
    ldfl_find_matching_rules("truncate", pathname, op_mask, &return_rules, &num_rules, &return_pcre_match);
    ldfl_apply_rules(return_rules, num_rules, return_pcre_match, pathname, &reworked_path);
    pcre2_match_data_free(return_pcre_match);
    if (num_rules > 0) {
        free(return_rules);
    };

    int ret = real_truncate(reworked_path, length);
    free(reworked_path);
    return ret;
}

int faccessat(int dirfd, const char *pathname, int mode, int flags) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "faccessat called: dirfd=%d, pathname=%s, mode=%d, flags=%d",
                        dirfd, pathname, mode, flags);
    RINIT;
    char               *reworked_path = NULL;
    compiled_mapping_t *return_rules;
    pcre2_match_data   *return_pcre_match = NULL;
    int                 num_rules         = 0;
    ldfl_find_matching_rules("faccessat", pathname, op_mask, &return_rules, &num_rules, &return_pcre_match);
    ldfl_apply_rules(return_rules, num_rules, return_pcre_match, pathname, &reworked_path);
    pcre2_match_data_free(return_pcre_match);
    if (num_rules > 0) {
        free(return_rules);
    };

    int ret = real_faccessat(dirfd, reworked_path, mode, flags);
    free(reworked_path);
    return ret;
}

int stat(const char *pathname, struct stat *statbuf) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "stat called: pathname=%s", pathname);
    RINIT;
    char               *reworked_path = NULL;
    compiled_mapping_t *return_rules;
    pcre2_match_data   *return_pcre_match = NULL;
    int                 num_rules         = 0;
    ldfl_find_matching_rules("stat", pathname, op_mask, &return_rules, &num_rules, &return_pcre_match);
    ldfl_apply_rules(return_rules, num_rules, return_pcre_match, pathname, &reworked_path);
    pcre2_match_data_free(return_pcre_match);
    if (num_rules > 0) {
        free(return_rules);
    };

    int ret = real_stat(reworked_path, statbuf);
    free(reworked_path);
    return ret;
}

int lstat(const char *pathname, struct stat *statbuf) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "lstat called: pathname=%s", pathname);
    RINIT;
    char               *reworked_path = NULL;
    compiled_mapping_t *return_rules;
    pcre2_match_data   *return_pcre_match = NULL;
    int                 num_rules         = 0;
    ldfl_find_matching_rules("lstat", pathname, op_mask, &return_rules, &num_rules, &return_pcre_match);
    ldfl_apply_rules(return_rules, num_rules, return_pcre_match, pathname, &reworked_path);
    pcre2_match_data_free(return_pcre_match);
    if (num_rules > 0) {
        free(return_rules);
    };

    int ret = real_lstat(reworked_path, statbuf);
    free(reworked_path);
    return ret;
}

int lchown(const char *pathname, uid_t owner, gid_t group) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;

    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "lchown called: pathname=%s, owner=%d, group=%d", pathname, owner,
                        group);
    RINIT;
    char               *reworked_path = NULL;
    compiled_mapping_t *return_rules;
    pcre2_match_data   *return_pcre_match = NULL;
    int                 num_rules         = 0;
    ldfl_find_matching_rules("lchown", pathname, op_mask, &return_rules, &num_rules, &return_pcre_match);
    ldfl_apply_rules(return_rules, num_rules, return_pcre_match, pathname, &reworked_path);
    pcre2_match_data_free(return_pcre_match);
    if (num_rules > 0) {
        free(return_rules);
    };

    int ret = real_lchown(reworked_path, owner, group);
    free(reworked_path);
    return ret;
}

int chown(const char *pathname, uid_t owner, gid_t group) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;

    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "chown called: pathname=%s, owner=%d, group=%d", pathname, owner,
                        group);
    RINIT;
    char               *reworked_path = NULL;
    compiled_mapping_t *return_rules;
    pcre2_match_data   *return_pcre_match = NULL;
    int                 num_rules         = 0;
    ldfl_find_matching_rules("chown", pathname, op_mask, &return_rules, &num_rules, &return_pcre_match);
    ldfl_apply_rules(return_rules, num_rules, return_pcre_match, pathname, &reworked_path);
    pcre2_match_data_free(return_pcre_match);
    if (num_rules > 0) {
        free(return_rules);
    };

    int ret = real_chown(reworked_path, owner, group);
    free(reworked_path);
    return ret;
}

int fchmodat(int dirfd, const char *pathname, mode_t mode, int flags) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;

    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "fchmodat called: dirfd=%d, pathname=%s, mode=%o, flags=%d", dirfd,
                        pathname, mode, flags);
    RINIT;
    char               *reworked_path = NULL;
    compiled_mapping_t *return_rules;
    pcre2_match_data   *return_pcre_match = NULL;
    int                 num_rules         = 0;
    ldfl_find_matching_rules("fchmodat", pathname, op_mask, &return_rules, &num_rules, &return_pcre_match);
    ldfl_apply_rules(return_rules, num_rules, return_pcre_match, pathname, &reworked_path);
    pcre2_match_data_free(return_pcre_match);
    if (num_rules > 0) {
        free(return_rules);
    };

    int ret = real_fchmodat(dirfd, reworked_path, mode, flags);
    free(reworked_path);
    return ret;
}

int symlinkat(const char *target, int newdirfd, const char *linkpathname) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;

    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "symlinkat called: target=%s, newdirfd=%d, linkpathname=%s",
                        target, newdirfd, linkpathname);
    RINIT;
    char               *reworked_path = NULL;
    compiled_mapping_t *return_rules;
    pcre2_match_data   *return_pcre_match = NULL;
    int                 num_rules         = 0;
    ldfl_find_matching_rules("symlinkat", linkpathname, op_mask, &return_rules, &num_rules, &return_pcre_match);
    ldfl_apply_rules(return_rules, num_rules, return_pcre_match, target, &reworked_path);
    pcre2_match_data_free(return_pcre_match);
    if (num_rules > 0) {
        free(return_rules);
    };

    int ret = real_symlinkat(reworked_path, newdirfd, linkpathname);
    free(reworked_path);
    return ret;
}

int mkfifo(const char *pathname, mode_t mode) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;

    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "mkfifo called: pathname=%s, mode=%o", pathname, mode);
    RINIT;
    char               *reworked_path = NULL;
    compiled_mapping_t *return_rules;
    pcre2_match_data   *return_pcre_match = NULL;
    int                 num_rules         = 0;
    ldfl_find_matching_rules("mkfifo", pathname, op_mask, &return_rules, &num_rules, &return_pcre_match);
    ldfl_apply_rules(return_rules, num_rules, return_pcre_match, pathname, &reworked_path);
    pcre2_match_data_free(return_pcre_match);
    if (num_rules > 0) {
        free(return_rules);
    };

    int ret = real_mkfifo(reworked_path, mode);
    free(reworked_path);
    return ret;
}

int mkfifoat(int dirfd, const char *pathname, mode_t mode) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;

    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "mkfifoat called: dirfd=%d, pathname=%s, mode=%o", dirfd, pathname,
                        mode);
    RINIT;
    char               *reworked_path = NULL;
    compiled_mapping_t *return_rules;
    pcre2_match_data   *return_pcre_match = NULL;
    int                 num_rules         = 0;
    ldfl_find_matching_rules("mkfifoat", pathname, op_mask, &return_rules, &num_rules, &return_pcre_match);
    ldfl_apply_rules(return_rules, num_rules, return_pcre_match, pathname, &reworked_path);
    pcre2_match_data_free(return_pcre_match);
    if (num_rules > 0) {
        free(return_rules);
    };

    int ret = real_mkfifoat(dirfd, reworked_path, mode);
    free(reworked_path);
    return ret;
}

int mknodat(int dirfd, const char *pathname, mode_t mode, dev_t dev) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;

    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "mknodat called: dirfd=%d, pathname=%s, mode=%o, dev=%lu", dirfd,
                        pathname, mode, (unsigned long)dev);
    RINIT;
    char               *reworked_path = NULL;
    compiled_mapping_t *return_rules;
    pcre2_match_data   *return_pcre_match = NULL;
    int                 num_rules         = 0;
    ldfl_find_matching_rules("mknodat", pathname, op_mask, &return_rules, &num_rules, &return_pcre_match);
    ldfl_apply_rules(return_rules, num_rules, return_pcre_match, pathname, &reworked_path);
    pcre2_match_data_free(return_pcre_match);
    if (num_rules > 0) {
        free(return_rules);
    };

    int ret = real_mknodat(dirfd, reworked_path, mode, dev);
    free(reworked_path);
    return ret;
}

int mknod(const char *pathname, mode_t mode, dev_t dev) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;

    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "mknod called: pathname=%s, mode=%o, dev=%lu", pathname, mode,
                        (unsigned long)dev);
    RINIT;
    char               *reworked_path = NULL;
    compiled_mapping_t *return_rules;
    pcre2_match_data   *return_pcre_match = NULL;
    int                 num_rules         = 0;
    ldfl_find_matching_rules("mknod", pathname, op_mask, &return_rules, &num_rules, &return_pcre_match);
    ldfl_apply_rules(return_rules, num_rules, return_pcre_match, pathname, &reworked_path);
    pcre2_match_data_free(return_pcre_match);
    if (num_rules > 0) {
        free(return_rules);
    };

    int ret = real_mknod(reworked_path, mode, dev);
    free(reworked_path);
    return ret;
}

int statx(int dirfd, const char *restrict pathname, int flags, unsigned int mask, struct statx *restrict statxbuf) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;

    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "statx called: dirfd=%d, pathname=%s, flags=%d, mask=%u", dirfd,
                        pathname, flags, mask);
    RINIT;
    char               *reworked_path = NULL;
    compiled_mapping_t *return_rules;
    pcre2_match_data   *return_pcre_match = NULL;
    int                 num_rules         = 0;
    ldfl_find_matching_rules("statx", pathname, op_mask, &return_rules, &num_rules, &return_pcre_match);
    ldfl_apply_rules(return_rules, num_rules, return_pcre_match, pathname, &reworked_path);
    pcre2_match_data_free(return_pcre_match);
    if (num_rules > 0) {
        free(return_rules);
    };

    int ret = real_statx(dirfd, reworked_path, flags, mask, statxbuf);
    free(reworked_path);
    return ret;
}

int creat(const char *pathname, mode_t mode) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;

    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "creat called: pathname=%s, mode=%o", pathname, mode);
    RINIT;
    char               *reworked_path = NULL;
    compiled_mapping_t *return_rules;
    pcre2_match_data   *return_pcre_match = NULL;
    int                 num_rules         = 0;
    ldfl_find_matching_rules("creat", pathname, op_mask, &return_rules, &num_rules, &return_pcre_match);
    ldfl_apply_rules(return_rules, num_rules, return_pcre_match, pathname, &reworked_path);
    pcre2_match_data_free(return_pcre_match);
    if (num_rules > 0) {
        free(return_rules);
    };

    int ret = real_creat(reworked_path, mode);
    free(reworked_path);

    return ret;
}

#if defined(__APPLE__)
int renamex_np(const char *oldpath, const char *newpath, int flags) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "renamex_np called: oldpath=%s, newpath=%s, flags=%d", oldpath,
                        newpath, flags);
    RINIT;
    char               *reworked_path = NULL;
    compiled_mapping_t *return_rules;
    pcre2_match_data   *return_pcre_match = NULL;
    int                 num_rules         = 0;
    ldfl_find_matching_rules("renamex_np", oldpath, op_mask, &return_rules, &num_rules, &return_pcre_match);
    ldfl_apply_rules(return_rules, num_rules, return_pcre_match, oldpath, &reworked_path);
    pcre2_match_data_free(return_pcre_match);
    if (num_rules > 0) {
        free(return_rules);
    };
    // TODO newpath

    int ret = real_renamex_np(reworked_path, newpath, flags);
    free(reworked_path);
    return ret;
}

int renameatx_np(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG,
                        "renameatx_np called: olddirfd=%d, oldpath=%s, newdirfd=%d, newpath=%s, flags=%d", olddirfd,
                        oldpath, newdirfd, newpath, flags);
    RINIT;
    char               *reworked_path = NULL;
    compiled_mapping_t *return_rules;
    pcre2_match_data   *return_pcre_match = NULL;
    int                 num_rules         = 0;
    ldfl_find_matching_rules("renameatx_np", oldpath, op_mask, &return_rules, &num_rules, &return_pcre_match);
    ldfl_apply_rules(return_rules, num_rules, return_pcre_match, pathname, &reworked_path);
    pcre2_match_data_free(return_pcre_match);
    if (num_rules > 0) {
        free(return_rules);
    };
    // TODO newpath

    int ret = real_renameatx_np(olddirfd, reworked_path, newdirfd, newpath, flags);
    free(reworked_path);
    return ret;
}
#endif

#endif
/** @endcond */
