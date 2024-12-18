#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
#define _BSD_SOURCE
#define _GNU_SOURCE
#define _XOPEN_SOURCE 500

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

// Bitmask flags for operation types
typedef enum {
    LDFL_LOG_FN_CALL        = 1ULL << 0, // Log LibC function calls
    LDFL_LOG_MAPPING_SEARCH = 1ULL << 1, // Log mapping search stuff
    LDFL_LOG_MAPPING_APPLY  = 1ULL << 2, // Log mapping application stuff
    LDFL_LOG_INIT           = 1ULL << 3, // Log for (de)initialization
    LDFL_LOG_ALL            = ~0ULL,     // Log everything
} ldfl_log_category_t;

// Bitmask flags for operation types
typedef enum {
    LDFL_OP_NOOP     = 1ULL << 0, // No operation
    LDFL_OP_MAP      = 1ULL << 1, // Map operation
    LDFL_OP_EXEC_MAP = 1ULL << 2, // Executable map
    LDFL_OP_MEM_OPEN = 1ULL << 3, // Memory open
    LDFL_OP_STATIC   = 1ULL << 4, // Static file
    LDFL_OP_PERM     = 1ULL << 5, // Change permissions/ownership
    LDFL_OP_DENY     = 1ULL << 6, // Deny access
    LDFL_OP_END      = 0ULL       // End marker
} ldfl_operation_t;

// Structure for a single mapping entry
typedef struct {
    const char      *name;           // Name of the mapping rule
    const char      *search_pattern; // Regex or pattern for the match
    ldfl_operation_t operation;      // Operation type (64-bit bitmask)
    const void      *target;         // Target resource (e.g., file pathname or blob pointer)
    const char      *extra_options;  // Additional options as a string
} ldfl_mapping_t;

// Variadic logger function type
typedef void (*ldfl_logger_t)(uint64_t mask, int priority, const char *fmt, ...);

// Structure for settings
typedef struct {
    int           log_level; // Log level (e.g., "debug", "info")
    ldfl_logger_t logger;    // Variadic logger function pointer
    uint64_t      log_mask;  // Log categories enabled
} ldfl_setting_t;

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
    vsyslog(priority, fmt, args);
    va_end(args);
    closelog();
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
    void   *_arg;                                                                                                      \
    void   *_args[LDFL_MAX_ARGS] = {0};                                                                                \
    int     _arg_count           = 0;                                                                                  \
    va_list va_list_name;                                                                                              \
    va_start(va_list_name, nvarg);                                                                                     \
    _arg = va_arg(va_list_name, void *);                                                                               \
                                                                                                                       \
    /* Extract arguments into the array */                                                                             \
    while (_arg != NULL) {                                                                                             \
        _args[_arg_count++] = _arg;                                                                                    \
        _arg                = va_arg(va_list_name, void *);                                                            \
    }                                                                                                                  \
    va_end(va_list_name);                                                                                              \
                                                                                                                       \
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_CRIT, "call '%s', variadic arg count too high: %d (limit: 8)",           \
                        #target_func, _arg_count);                                                                     \
    /* Call the target function based on the argument count */                                                         \
    int ret;                                                                                                           \
    switch (_arg_count) {                                                                                              \
    case 0:                                                                                                            \
        ret = target_func(__VA_ARGS__, NULL);                                                                          \
        break;                                                                                                         \
    case 1:                                                                                                            \
        ret = target_func(__VA_ARGS__, _args[0], NULL);                                                                \
        break;                                                                                                         \
    case 2:                                                                                                            \
        ret = target_func(__VA_ARGS__, _args[0], _args[1], NULL);                                                      \
        break;                                                                                                         \
    case 3:                                                                                                            \
        ret = target_func(__VA_ARGS__, _args[0], _args[1], _args[2], NULL);                                            \
        break;                                                                                                         \
    case 4:                                                                                                            \
        ret = target_func(__VA_ARGS__, _args[0], _args[1], _args[2], _args[3], NULL);                                  \
        break;                                                                                                         \
    case 5:                                                                                                            \
        ret = target_func(__VA_ARGS__, _args[0], _args[1], _args[2], _args[3], _args[4], NULL);                        \
        break;                                                                                                         \
    case 6:                                                                                                            \
        ret = target_func(__VA_ARGS__, _args[0], _args[1], _args[2], _args[3], _args[4], _args[5], NULL);              \
        break;                                                                                                         \
    case 7:                                                                                                            \
        ret = target_func(__VA_ARGS__, _args[0], _args[1], _args[2], _args[3], _args[4], _args[5], _args[6], NULL);    \
        break;                                                                                                         \
    case 8:                                                                                                            \
        ret = target_func(__VA_ARGS__, _args[0], _args[1], _args[2], _args[3], _args[4], _args[5], _args[6], _args[7], \
                          NULL);                                                                                       \
        break;                                                                                                         \
    default:                                                                                                           \
        ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_CRIT, "call '%s', variadic arg count too high: %d (limit: 8)",       \
                            #target_func, _arg_count);                                                                 \
        ret = -1; /* Too many arguments */                                                                             \
    }

#define ldfl_variadic_mode_wrap(target_func, ...)                                                                      \
    int     ret;                                                                                                       \
    va_list _args;                                                                                                     \
    mode_t  mode = 0;                                                                                                  \
    if ((flags & O_CREAT) || (flags & O_TMPFILE)) {                                                                    \
        va_start(_args, flags);                                                                                        \
        mode = va_arg(_args, mode_t);                                                                                  \
        va_end(_args);                                                                                                 \
        ret = target_func(__VA_ARGS__, mode);                                                                          \
    } else {                                                                                                           \
        ret = target_func(__VA_ARGS__);                                                                                \
    }

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

        ldfl_compiled_rules[i].mapping        = &ldfl_mapping[i];
        ldfl_compiled_rules[i].matching_regex = re;
    }
}

// Free compiled regex data
void ldfl_regex_free() {
    for (int i = 0; i < ldfl_rule_count; i++) {
        pcre2_code_free(ldfl_compiled_rules[i].matching_regex);
    }
    free(ldfl_compiled_rules);
}

bool ldfl_find_matching_rule(const char *call, const char *pathname, uint64_t mask, compiled_mapping_t *return_rule,
                             pcre2_match_data **return_pcre_match) {
    for (int i = 0; i < ldfl_rule_count; i++) {
        ldfl_setting.logger(LDFL_LOG_MAPPING_SEARCH, LOG_DEBUG, "rule[%s] not relevant for call '%s', skipping",
                            ldfl_mapping[i].name, call);
        // Rule not matching
        if (!(ldfl_compiled_rules[i].mapping->operation & mask)) {
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
        if (rc > 0) {
            ldfl_setting.logger(LDFL_LOG_MAPPING_SEARCH, LOG_INFO,
                                "rule[%s] match pathname '%s', selected for call '%s'", ldfl_mapping[i].name, pathname,
                                call);
            return_pcre_match = &match_data;
            return_rule       = &ldfl_compiled_rules[i];
            return true;
        } else {
            ldfl_setting.logger(LDFL_LOG_MAPPING_SEARCH, LOG_DEBUG, "rule[%s] not matching pathname '%s' for call '%s'",
                                ldfl_mapping[i].name, pathname, call);
            pcre2_match_data_free(match_data);
        }
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
            if (!getcwd(dir_path, sizeof(dir_path))) {
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
            return NULL;
        }

        resolved_path = realpath(combined_path, NULL);
    }

    if (!resolved_path) {
        perror("realpath");
    }

    return resolved_path;
}

void ldfl_apply_rule(compiled_mapping_t mapping_rule, pcre2_match_data *match_group, const char *pathname) {
    switch (mapping_rule.mapping->operation) {
    case LDFL_OP_NOOP:
        break;
    case LDFL_OP_MAP:
        break;
    case LDFL_OP_EXEC_MAP:
        break;
    case LDFL_OP_MEM_OPEN:
        break;
    case LDFL_OP_STATIC:
        break;
    case LDFL_OP_PERM:
        break;
    case LDFL_OP_DENY:
        break;
    default:
        ldfl_setting.logger(LDFL_LOG_MAPPING_APPLY, LOG_WARNING, "Unhandled operation for: %s\n", pathname);
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
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match = NULL;
    if (ldfl_find_matching_rule("fopen", pathname, op_mask, &return_rule, &return_pcre_match)) {
    }
    pcre2_match_data_free(return_pcre_match);

    return real_fopen(pathname, mode);
}

FILE *fopen64(const char *pathname, const char *mode) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "fopen64 called: pathname=%s, mode=%s", pathname, mode);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match = NULL;
    if (ldfl_find_matching_rule("fopen64", pathname, op_mask, &return_rule, &return_pcre_match)) {
    }
    pcre2_match_data_free(return_pcre_match);

    return real_fopen64(pathname, mode);
}

int openat(int dirfd, const char *pathname, int flags, ...) {
    va_list args;
    va_start(args, flags);

    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    // FIXME handle variadic properly
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "openat called: dirfd=%d, pathname=%s, flags=%d, mode=%o", dirfd,
                        pathname, flags, va_arg(args, mode_t));
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match = NULL;
    if (ldfl_find_matching_rule("openat", pathname, op_mask, &return_rule, &return_pcre_match)) {
    }
    pcre2_match_data_free(return_pcre_match);
    va_end(args);
    ldfl_variadic_mode_wrap(real_openat, dirfd, pathname, flags);
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
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match = NULL;
    if (ldfl_find_matching_rule("open", pathname, op_mask, &return_rule, &return_pcre_match)) {
    }
    pcre2_match_data_free(return_pcre_match);

    va_end(args);
    ldfl_variadic_mode_wrap(real_open, pathname, flags);
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
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match = NULL;
    if (ldfl_find_matching_rule("open64", pathname, op_mask, &return_rule, &return_pcre_match)) {
    }
    pcre2_match_data_free(return_pcre_match);

    va_end(args);
    ldfl_variadic_mode_wrap(real_open64, pathname, flags);
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
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match = NULL;
    if (ldfl_find_matching_rule("openat64", pathname, op_mask, &return_rule, &return_pcre_match)) {
    }
    pcre2_match_data_free(return_pcre_match);

    va_end(args);
    ldfl_variadic_mode_wrap(real_openat64, dirfd, pathname, flags);
    return ret;
}

int rename(const char *oldpath, const char *newpath) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "rename called: oldpath=%s, newpath=%s", oldpath, newpath);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match = NULL;
    if (ldfl_find_matching_rule("rename", oldpath, op_mask, &return_rule, &return_pcre_match)) {
    }
    pcre2_match_data_free(return_pcre_match);
    // TODO newpath
    return real_rename(oldpath, newpath);
}

int renameat2(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    REAL(renameat2);
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG,
                        "renameat2 called: olddirfd=%d, oldpath=%s, newdirfd=%d, newpath=%s, flags=%u", olddirfd,
                        oldpath, newdirfd, newpath, flags);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match = NULL;
    if (ldfl_find_matching_rule("olddirfd", oldpath, op_mask, &return_rule, &return_pcre_match)) {
    }
    pcre2_match_data_free(return_pcre_match);
    // TODO newpath

    return real_renameat2(olddirfd, oldpath, newdirfd, newpath, flags);
}

int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG,
                        "renameat called: olddirfd=%d, oldpath=%s, newdirfd=%d, newpath=%s", olddirfd, oldpath,
                        newdirfd, newpath);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match = NULL;
    if (ldfl_find_matching_rule("renameat", oldpath, op_mask, &return_rule, &return_pcre_match)) {
    }
    pcre2_match_data_free(return_pcre_match);
    // TODO newpath

    return real_renameat(olddirfd, oldpath, newdirfd, newpath);
}

int unlink(const char *pathname) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "unlink called: pathname=%s", pathname);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match = NULL;
    if (ldfl_find_matching_rule("unlink", pathname, op_mask, &return_rule, &return_pcre_match)) {
    }
    pcre2_match_data_free(return_pcre_match);

    return real_unlink(pathname);
}

int unlinkat(int dirfd, const char *pathname, int flags) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "unlinkat called: dirfd=%d, pathname=%s, flags=%d", dirfd,
                        pathname, flags);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match = NULL;
    if (ldfl_find_matching_rule("unlinkat", pathname, op_mask, &return_rule, &return_pcre_match)) {
    }
    pcre2_match_data_free(return_pcre_match);

    return real_unlinkat(dirfd, pathname, flags);
}

int utime(const char *pathname, const struct utimbuf *times) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "utimes called: pathname=%s, times=[%ld, %ld]", pathname,
                        (times == NULL) ? 0 : times->actime, (times == NULL) ? 0 : times->modtime);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match = NULL;
    if (ldfl_find_matching_rule("utime", pathname, op_mask, &return_rule, &return_pcre_match)) {
    }
    pcre2_match_data_free(return_pcre_match);

    return real_utime(pathname, times);
}

int utimes(const char *pathname, const struct timeval times[2]) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "utimes called: pathname=%s, times=[%ld:%ld, %ld:%ld]", pathname,
                        (times == NULL) ? 0 : times[0].tv_sec, (times == NULL) ? 0 : times[0].tv_usec,
                        (times == NULL) ? 0 : times[1].tv_sec, (times == NULL) ? 0 : times[1].tv_usec);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match = NULL;
    if (ldfl_find_matching_rule("utimes", pathname, op_mask, &return_rule, &return_pcre_match)) {
    }
    pcre2_match_data_free(return_pcre_match);

    return real_utimes(pathname, times);
}

int access(const char *pathname, int mode) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "access called: pathname=%s, mode=%d", pathname, mode);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match = NULL;
    if (ldfl_find_matching_rule("access", pathname, op_mask, &return_rule, &return_pcre_match)) {
    }
    pcre2_match_data_free(return_pcre_match);

    return real_access(pathname, mode);
}

int fstatat(int dirfd, const char *pathname, struct stat *statbuf, int flags) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "fstatat called: dirfd=%d, pathname=%s, flags=%d", dirfd, pathname,
                        flags);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match = NULL;
    if (ldfl_find_matching_rule("fstatat", pathname, op_mask, &return_rule, &return_pcre_match)) {
    }
    pcre2_match_data_free(return_pcre_match);

    return real_fstatat(dirfd, pathname, statbuf, flags);
}

int __xstat(int version, const char *pathname, struct stat *statbuf) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "__xstat called: version=%d, pathname=%s", version, pathname);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match = NULL;
    if (ldfl_find_matching_rule("__xstat", pathname, op_mask, &return_rule, &return_pcre_match)) {
    }
    pcre2_match_data_free(return_pcre_match);

    return real___xstat(version, pathname, statbuf);
}

int __xstat64(int version, const char *pathname, struct stat *statbuf) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "__xstat64 called: version=%d, pathname=%s", version, pathname);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match = NULL;
    if (ldfl_find_matching_rule("__xstat64", pathname, op_mask, &return_rule, &return_pcre_match)) {
    }
    pcre2_match_data_free(return_pcre_match);

    return real___xstat64(version, pathname, statbuf);
}

int __lxstat(int version, const char *pathname, struct stat *statbuf) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "__lxstat called: version=%d, pathname=%s", version, pathname);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match = NULL;
    if (ldfl_find_matching_rule("__lxstat", pathname, op_mask, &return_rule, &return_pcre_match)) {
    }
    pcre2_match_data_free(return_pcre_match);

    return real___lxstat(version, pathname, statbuf);
}

int __fxstatat(int version, int dirfd, const char *pathname, struct stat *statbuf, int flags) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "__fxstatat called: version=%d, dirfd=%d, pathname=%s, flags=%d",
                        version, dirfd, pathname, flags);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match = NULL;
    if (ldfl_find_matching_rule("__fxstatat", pathname, op_mask, &return_rule, &return_pcre_match)) {
    }
    pcre2_match_data_free(return_pcre_match);

    return real___fxstatat(version, dirfd, pathname, statbuf, flags);
}

int utimensat(int dirfd, const char *pathname, const struct timespec times[2], int flags) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG,
                        "utimensat called: dirfd=%d, pathname=%s, times=[%ld, %ld], flags=%d", dirfd, pathname,
                        (times == NULL) ? 0 : times[0].tv_sec, (times == NULL) ? 0 : times[1].tv_sec, flags);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match = NULL;
    if (ldfl_find_matching_rule("utimensat", pathname, op_mask, &return_rule, &return_pcre_match)) {
    }
    pcre2_match_data_free(return_pcre_match);

    return real_utimensat(dirfd, pathname, times, flags);
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
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match = NULL;
    if (ldfl_find_matching_rule("execve", pathname, op_mask, &return_rule, &return_pcre_match)) {
    }
    pcre2_match_data_free(return_pcre_match);
    // TODO argv[0]

    return real_execve(pathname, argv, envp);
}

int execl(const char *pathname, const char *arg, ...) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_EXEC_MAP | LDFL_OP_DENY;
    va_list  args;
    va_start(args, arg);
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "execl called: pathname=%s, arg=%s", pathname, arg);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match = NULL;
    if (ldfl_find_matching_rule("execl", pathname, op_mask, &return_rule, &return_pcre_match)) {
    }
    pcre2_match_data_free(return_pcre_match);
    // TODO argv[0]

    va_end(args);
    ldfl_variadic_str_wrap(real_execl, arg, pathname, arg);
    return ret;
}

int execlp(const char *file, const char *arg, ...) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_EXEC_MAP | LDFL_OP_DENY;
    va_list  args;
    va_start(args, arg);
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "execlp called: file=%s, arg=%s", file, arg);
    va_end(args);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match = NULL;
    if (ldfl_find_matching_rule("execlp", file, op_mask, &return_rule, &return_pcre_match)) {
    }
    pcre2_match_data_free(return_pcre_match);
    // TODO argv[0]

    ldfl_variadic_str_wrap(real_execlp, arg, file, arg);
    return ret;
}

int execv(const char *pathname, char *const argv[]) {
    uint64_t op_mask  = LDFL_OP_NOOP | LDFL_OP_EXEC_MAP | LDFL_OP_DENY;
    char    *argv_str = ldfl_render_nullable_array(argv);
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "execv called: pathname=%s, argv=%s", pathname, argv_str);
    free(argv_str);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match = NULL;
    if (ldfl_find_matching_rule("execv", pathname, op_mask, &return_rule, &return_pcre_match)) {
    }
    pcre2_match_data_free(return_pcre_match);
    // TODO argv[0]

    return real_execv(pathname, argv);
}

int execvp(const char *file, char *const argv[]) {
    uint64_t op_mask  = LDFL_OP_NOOP | LDFL_OP_EXEC_MAP | LDFL_OP_DENY;
    char    *argv_str = ldfl_render_nullable_array(argv);
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "execvp called: file=%s, argv=%s", file, argv_str);
    free(argv_str);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match = NULL;
    if (ldfl_find_matching_rule("execvp", file, op_mask, &return_rule, &return_pcre_match)) {
    }
    pcre2_match_data_free(return_pcre_match);
    // TODO argv[0]

    return real_execvp(file, argv);
}

DIR *opendir(const char *name) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "opendir called: name=%s", name);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match = NULL;
    if (ldfl_find_matching_rule("opendir", name, op_mask, &return_rule, &return_pcre_match)) {
    }
    pcre2_match_data_free(return_pcre_match);

    return real_opendir(name);
}

int mkdir(const char *pathname, mode_t mode) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "mkdir called: pathname=%s, mode=%o", pathname, mode);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match = NULL;
    if (ldfl_find_matching_rule("mkdir", pathname, op_mask, &return_rule, &return_pcre_match)) {
    }
    pcre2_match_data_free(return_pcre_match);

    return real_mkdir(pathname, mode);
}

int mkdirat(int dirfd, const char *pathname, mode_t mode) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "mkdirat called: dirfd=%d, pathname=%s, mode=%o", dirfd, pathname,
                        mode);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match = NULL;
    if (ldfl_find_matching_rule("mkdirat", pathname, op_mask, &return_rule, &return_pcre_match)) {
    }
    pcre2_match_data_free(return_pcre_match);

    return real_mkdirat(dirfd, pathname, mode);
}

int rmdir(const char *pathname) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "rmdir called: pathname=%s", pathname);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match = NULL;
    if (ldfl_find_matching_rule("rmdir", pathname, op_mask, &return_rule, &return_pcre_match)) {
    }
    pcre2_match_data_free(return_pcre_match);

    return real_rmdir(pathname);
}

int chdir(const char *pathname) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "chdir called: pathname=%s", pathname);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match = NULL;
    if (ldfl_find_matching_rule("chdir", pathname, op_mask, &return_rule, &return_pcre_match)) {
    }
    pcre2_match_data_free(return_pcre_match);

    return real_chdir(pathname);
}

int symlink(const char *target, const char *linkpathname) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "symlink called: target=%s, linkpathname=%s", target,
                        linkpathname);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match = NULL;
    if (ldfl_find_matching_rule("symlink", linkpathname, op_mask, &return_rule, &return_pcre_match)) {
    }
    pcre2_match_data_free(return_pcre_match);
    // TODO target

    return real_symlink(target, linkpathname);
}

ssize_t readlink(const char *pathname, char *buf, size_t bufsiz) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "readlink called: pathname=%s, bufsiz=%zu", pathname, bufsiz);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match = NULL;
    if (ldfl_find_matching_rule("readlink", pathname, op_mask, &return_rule, &return_pcre_match)) {
    }
    pcre2_match_data_free(return_pcre_match);

    return real_readlink(pathname, buf, bufsiz);
}

int link(const char *oldpath, const char *newpath) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "link called: oldpath=%s, newpath=%s", oldpath, newpath);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match = NULL;
    if (ldfl_find_matching_rule("link", oldpath, op_mask, &return_rule, &return_pcre_match)) {
    }
    pcre2_match_data_free(return_pcre_match);
    // TODO newpath

    return real_link(oldpath, newpath);
}

int linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG,
                        "linkat called: olddirfd=%d, oldpath=%s, newdirfd=%d, newpath=%s, flags=%d", olddirfd, oldpath,
                        newdirfd, newpath, flags);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match = NULL;
    if (ldfl_find_matching_rule("linkat", oldpath, op_mask, &return_rule, &return_pcre_match)) {
    }
    pcre2_match_data_free(return_pcre_match);
    // TODO newpath

    return real_linkat(olddirfd, oldpath, newdirfd, newpath, flags);
}

int chmod(const char *pathname, mode_t mode) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "chmod called: pathname=%s, mode=%o", pathname, mode);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match = NULL;
    if (ldfl_find_matching_rule("chmod", pathname, op_mask, &return_rule, &return_pcre_match)) {
    }
    pcre2_match_data_free(return_pcre_match);

    return real_chmod(pathname, mode);
}

int truncate(const char *pathname, off_t length) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "truncate called: pathname=%s, length=%ld", pathname, length);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match = NULL;
    if (ldfl_find_matching_rule("truncate", pathname, op_mask, &return_rule, &return_pcre_match)) {
    }
    pcre2_match_data_free(return_pcre_match);

    return real_truncate(pathname, length);
}

int faccessat(int dirfd, const char *pathname, int mode, int flags) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "faccessat called: dirfd=%d, pathname=%s, mode=%d, flags=%d",
                        dirfd, pathname, mode, flags);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match = NULL;
    if (ldfl_find_matching_rule("faccessat", pathname, op_mask, &return_rule, &return_pcre_match)) {
    }
    pcre2_match_data_free(return_pcre_match);

    return real_faccessat(dirfd, pathname, mode, flags);
}

int stat(const char *pathname, struct stat *statbuf) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "stat called: pathname=%s", pathname);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match = NULL;
    if (ldfl_find_matching_rule("stat", pathname, op_mask, &return_rule, &return_pcre_match)) {
    }
    pcre2_match_data_free(return_pcre_match);

    return real_stat(pathname, statbuf);
}

int lstat(const char *pathname, struct stat *statbuf) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "lstat called: pathname=%s", pathname);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match = NULL;
    if (ldfl_find_matching_rule("lstat", pathname, op_mask, &return_rule, &return_pcre_match)) {
    }
    pcre2_match_data_free(return_pcre_match);

    return real_lstat(pathname, statbuf);
}

int lchown(const char *pathname, uid_t owner, gid_t group) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;

    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "lchown called: pathname=%s, owner=%d, group=%d", pathname, owner,
                        group);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match = NULL;
    if (ldfl_find_matching_rule("lchown", pathname, op_mask, &return_rule, &return_pcre_match)) {
    }
    pcre2_match_data_free(return_pcre_match);

    return real_lchown(pathname, owner, group);
}

int chown(const char *pathname, uid_t owner, gid_t group) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;

    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "chown called: pathname=%s, owner=%d, group=%d", pathname, owner,
                        group);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match = NULL;
    if (ldfl_find_matching_rule("chown", pathname, op_mask, &return_rule, &return_pcre_match)) {
    }
    pcre2_match_data_free(return_pcre_match);

    return real_chown(pathname, owner, group);
}

int fchmodat(int dirfd, const char *pathname, mode_t mode, int flags) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;

    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "fchmodat called: dirfd=%d, pathname=%s, mode=%o, flags=%d", dirfd,
                        pathname, mode, flags);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match = NULL;
    if (ldfl_find_matching_rule("fchmodat", pathname, op_mask, &return_rule, &return_pcre_match)) {
    }
    pcre2_match_data_free(return_pcre_match);

    return real_fchmodat(dirfd, pathname, mode, flags);
}

int symlinkat(const char *target, int newdirfd, const char *linkpathname) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;

    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "symlinkat called: target=%s, newdirfd=%d, linkpathname=%s",
                        target, newdirfd, linkpathname);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match = NULL;
    if (ldfl_find_matching_rule("symlinkat", linkpathname, op_mask, &return_rule, &return_pcre_match)) {
    }
    pcre2_match_data_free(return_pcre_match);

    return real_symlinkat(target, newdirfd, linkpathname);
}

int mkfifo(const char *pathname, mode_t mode) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;

    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "mkfifo called: pathname=%s, mode=%o", pathname, mode);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match = NULL;
    if (ldfl_find_matching_rule("mkfifo", pathname, op_mask, &return_rule, &return_pcre_match)) {
    }
    pcre2_match_data_free(return_pcre_match);

    return real_mkfifo(pathname, mode);
}

int mkfifoat(int dirfd, const char *pathname, mode_t mode) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;

    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "mkfifoat called: dirfd=%d, pathname=%s, mode=%o", dirfd, pathname,
                        mode);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match = NULL;
    if (ldfl_find_matching_rule("mkfifoat", pathname, op_mask, &return_rule, &return_pcre_match)) {
    }
    pcre2_match_data_free(return_pcre_match);

    return real_mkfifoat(dirfd, pathname, mode);
}

int mknodat(int dirfd, const char *pathname, mode_t mode, dev_t dev) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;

    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "mknodat called: dirfd=%d, pathname=%s, mode=%o, dev=%lu", dirfd,
                        pathname, mode, (unsigned long)dev);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match = NULL;
    if (ldfl_find_matching_rule("mknodat", pathname, op_mask, &return_rule, &return_pcre_match)) {
    }
    pcre2_match_data_free(return_pcre_match);

    return real_mknodat(dirfd, pathname, mode, dev);
}

int mknod(const char *pathname, mode_t mode, dev_t dev) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;

    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "mknod called: pathname=%s, mode=%o, dev=%lu", pathname, mode,
                        (unsigned long)dev);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match = NULL;
    if (ldfl_find_matching_rule("mknod", pathname, op_mask, &return_rule, &return_pcre_match)) {
    }
    pcre2_match_data_free(return_pcre_match);

    return real_mknod(pathname, mode, dev);
}

int statx(int dirfd, const char *restrict pathname, int flags, unsigned int mask, struct statx *restrict statxbuf) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;

    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "statx called: dirfd=%d, pathname=%s, flags=%d, mask=%u", dirfd,
                        pathname, flags, mask);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match = NULL;
    if (ldfl_find_matching_rule("statx", pathname, op_mask, &return_rule, &return_pcre_match)) {
    }
    pcre2_match_data_free(return_pcre_match);

    return real_statx(dirfd, pathname, flags, mask, statxbuf);
}

int creat(const char *pathname, mode_t mode) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;

    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "creat called: pathname=%s, mode=%o", pathname, mode);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match = NULL;
    if (ldfl_find_matching_rule("creat", pathname, op_mask, &return_rule, &return_pcre_match)) {
    }
    pcre2_match_data_free(return_pcre_match);

    return real_creat(pathname, mode);
}

#if defined(__APPLE__)
int renamex_np(const char *oldpath, const char *newpath, int flags) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG, "renamex_np called: oldpath=%s, newpath=%s, flags=%d", oldpath,
                        newpath, flags);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match = NULL;
    if (ldfl_find_matching_rule("renamex_np", oldpath, op_mask, &return_rule, &return_pcre_match)) {
    }
    pcre2_match_data_free(return_pcre_match);
    // TODO newpath

    return real_renamex_np(oldpath, newpath, flags);
}

int renameatx_np(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags) {
    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LDFL_LOG_FN_CALL, LOG_DEBUG,
                        "renameatx_np called: olddirfd=%d, oldpath=%s, newdirfd=%d, newpath=%s, flags=%d", olddirfd,
                        oldpath, newdirfd, newpath, flags);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match = NULL;
    if (ldfl_find_matching_rule("renameatx_np", oldpath, op_mask, &return_rule, &return_pcre_match)) {
    }
    pcre2_match_data_free(return_pcre_match);
    // TODO newpath
    //
    return real_renameatx_np(olddirfd, oldpath, newdirfd, newpath, flags);
}
#endif

#endif
