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
#include <glob.h>
#include <unistd.h>

#include <syslog.h>
#ifndef PCRE2_CODE_UNIT_WIDTH
#define PCRE2_CODE_UNIT_WIDTH 8
#endif
#include <pcre2.h>

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
void ldfl_dummy_logger(int priority, const char *fmt, ...) {
    return;
}

// log to stderr logger
void ldfl_stderr_logger(int priority, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    if (priority > ldfl_setting.log_level)
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
void ldfl_syslog_logger(int priority, const char *fmt, ...) {
    if (priority > ldfl_setting.log_level)
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
// TODO fix path
#include "../cfg/ldfl-config.h"
#endif

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
            ldfl_setting.logger(LOG_CRIT, "rule[%s], PCRE2 compilation failed at offset %d: %s\n", ldfl_mapping[i].name,
                                (int)erroroffset, buffer);
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

bool ldfl_find_matching_rule(const char *call, const char *path, uint64_t mask, compiled_mapping_t *return_rule,
                             pcre2_match_data **return_pcre_match) {
    for (int i = 0; i < ldfl_rule_count; i++) {
        ldfl_setting.logger(LOG_DEBUG, "rule[%s] not relevant for call '%s', skipping", ldfl_mapping[i].name, call);
        // Rule not matching
        if (!(ldfl_compiled_rules[i].mapping->operation & mask)) {
            ldfl_setting.logger(LOG_DEBUG, "rule[%s] not relevant for call '%s', skipping", ldfl_mapping[i].name, call);
            continue;
        }

        pcre2_match_data *match_data =
            pcre2_match_data_create_from_pattern(ldfl_compiled_rules[i].matching_regex, NULL);

        int rc = pcre2_match(ldfl_compiled_rules[i].matching_regex, // The compiled pattern
                             (PCRE2_SPTR)path,                      // The subject string
                             strlen(path),                          // Length of the subject
                             0,                                     // Start at offset 0
                             0,                                     // Default options
                             match_data,                            // Match data structure
                             NULL                                   // Default match context
        );
        if (rc > 0) {
            ldfl_setting.logger(LOG_INFO, "rule[%s] match path '%s', selected for call '%s'", ldfl_mapping[i].name,
                                path, call);
            return_pcre_match = &match_data;
            return_rule       = &ldfl_compiled_rules[i];
            return true;
        } else {
            ldfl_setting.logger(LOG_DEBUG, "rule[%s] not matching path '%s' for call '%s'", ldfl_mapping[i].name, path,
                                call);
            // pcre2_match_data_free(match_data);
        }
    }
    return false;
}

// Macro used for testing
// this permits to test the utils function without enabling the libc wrappers.
#ifndef LDLF_UTILS_TESTING

#define REAL(f)                                                                                                        \
    real_##f = dlsym(RTLD_NEXT, #f);                                                                                   \
    assert(real_##f != NULL)

#define RINIT                                                                                                          \
    if (!ldfl_is_init) {                                                                                               \
        ldfl_setting.logger(LOG_DEBUG, "ld-fliar init did not run, re-init");                                          \
        ldfl_init();                                                                                                   \
    };

// Flag to check if ldfl is properly initialized
// FIXME concurrency issue, add some locking when doing the init
bool ldfl_is_init;

// libc functions doing the real job
int (*real_openat)(int dirfd, const char *pathname, int flags, mode_t mode);
FILE *(*real_fopen)(const char *filename, const char *mode);
FILE *(*real_fopen64)(const char *filename, const char *mode);
FILE *(*real_freopen)(const char *restrict pathname, const char *restrict mode, FILE *restrict stream);
int (*real_open)(const char *pathname, int flags, mode_t mode);
int (*real_open64)(const char *pathname, int flags, mode_t mode);
int (*real_openat64)(int dirfd, const char *pathname, int flags, mode_t mode);
int (*real_rename)(const char *oldpath, const char *newpath);
int (*real_renameat2)(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags);
int (*real_renameat)(int olddirfd, const char *oldpath, int newdirfd, const char *newpath);
int (*real_unlink)(const char *pathname);
int (*real_unlinkat)(int dirfd, const char *pathname, int flags);
int (*real_utimes)(const char *filename, const struct timeval times[2]);
int (*real_access)(const char *pathname, int mode);
int (*real_fstatat)(int dirfd, const char *pathname, struct stat *statbuf, int flags);
int (*real___xstat)(int version, const char *filename, struct stat *statbuf);
int (*real___xstat64)(int version, const char *filename, struct stat *statbuf);
int (*real___lxstat)(int version, const char *filename, struct stat *statbuf);
int (*real___fxstatat)(int version, int dirfd, const char *pathname, struct stat *statbuf, int flags);
int (*real_utimensat)(int dirfd, const char *pathname, const struct timespec times[2], int flags);
int (*real_execve)(const char *filename, char *const argv[], char *const envp[]);
int (*real_execl)(const char *path, const char *arg, ...);
int (*real_execlp)(const char *file, const char *arg, ...);
int (*real_execv)(const char *path, char *const argv[]);
int (*real_execvp)(const char *file, char *const argv[]);
int (*real_glob)(const char *pattern, int flags, int (*errfunc)(const char *, int), glob_t *pglob);
DIR *(*real_opendir)(const char *name);
int (*real_mkdir)(const char *pathname, mode_t mode);
int (*real_mkdirat)(int dirfd, const char *pathname, mode_t mode);
int (*real_rmdir)(const char *pathname);
int (*real_chdir)(const char *path);
int (*real_symlink)(const char *target, const char *linkpath);
ssize_t (*real_readlink)(const char *pathname, char *buf, size_t bufsiz);
int (*real_link)(const char *oldpath, const char *newpath);
int (*real_linkat)(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags);
int (*real_chmod)(const char *path, mode_t mode);
int (*real_truncate)(const char *path, off_t length);
int (*real_faccessat)(int dirfd, const char *pathname, int mode, int flags);
int (*real_stat)(const char *pathname, struct stat *statbuf);
int (*real_lstat)(const char *pathname, struct stat *statbuf);
int (*real_lchown)(const char *pathname, uid_t owner, gid_t group);
int (*real_chown)(const char *pathname, uid_t owner, gid_t group);
int (*real_fchmodat)(int dirfd, const char *pathname, mode_t mode, int flags);
ssize_t (*real_readlink)(const char *restrict pathname, char *restrict buf, size_t bufsiz);
ssize_t (*real_readlinkat)(int dirfd, const char *restrict pathname, char *restrict buf, size_t bufsiz);
int (*real_symlinkat)(const char *target, int newdirfd, const char *linkpath);
int (*real_mkfifo)(const char *pathname, mode_t mode);
int (*real_mkfifoat)(int dirfd, const char *pathname, mode_t mode);
int (*real_mknodat)(int dirfd, const char *pathname, mode_t mode, dev_t dev);
int (*real_mknod)(const char *pathname, mode_t mode, dev_t dev);
int (*real_statx)(int dirfd, const char *restrict pathname, int flags, unsigned int mask,
                  struct statx *restrict statxbuf);
int (*real_creat)(const char *pathname, mode_t mode);
int (*real_lstat)(const char *restrict pathname, struct stat *restrict statbuf);

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
    ldfl_setting.logger(LOG_DEBUG, "ld-fliar init called");
    ldfl_regex_init();
    REAL(fopen);
    REAL(fopen64);
    REAL(freopen);
    REAL(open);
    REAL(creat);
    REAL(open64);
    REAL(openat);
    REAL(openat64);
    REAL(rename);
    REAL(renameat);
    REAL(renameat2);
    REAL(utimes);
    REAL(utimensat);
    REAL(access);
    REAL(faccessat);
    REAL(stat);
    REAL(lstat);
    REAL(fstatat);
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
    REAL(opendir);
    REAL(mkdir);
    REAL(mkdirat);
    REAL(mknod);
    REAL(mknodat);
    REAL(mkfifo);
    REAL(mkfifoat);
    REAL(rmdir);
    REAL(chdir);
    REAL(symlink);
    REAL(symlinkat);
    REAL(readlink);
    REAL(readlinkat);
    REAL(link);
    REAL(linkat);
    REAL(unlink);
    REAL(unlinkat);
    REAL(chmod);
    REAL(chown);
    REAL(lchown);
    REAL(truncate);
    REAL(glob);

    // REAL(__fxstat);
    // REAL(futimens);
    // REAL(fdopendir);
    // REAL(fchdir);
    // REAL(fchmod);
    // REAL(ftruncate);
    // REAL(lseek);
    // REAL(futimes);
    // REAL(fchmodat);
    // REAL(fstat);
    // REAL(getcwd);

#if defined(__APPLE__)
    REAL(renamex_np);
    REAL(renameatx_np);
#endif
    ldfl_is_init = true;
    ldfl_setting.logger(LOG_DEBUG, "initialized");
}

// de-init function
// free compiled regexp
static void __attribute__((destructor(101))) ldfl_dinit() {
    ldfl_setting.logger(LOG_DEBUG, "ld-fliar dinit called");
    ldfl_regex_free();
    ldfl_setting.logger(LOG_DEBUG, "freed");
}

int openat(int dirfd, const char *pathname, int flags, mode_t mode) {
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_EXEC_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LOG_DEBUG, "openat called: dirfd=%d, pathname=%s, flags=%d, mode=%o", dirfd, pathname, flags,
                        mode);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match;
    ldfl_find_matching_rule("openat", pathname, op_mask, &return_rule, &return_pcre_match);
    // pcre2_match_data_free(return_pcre_match);

    return real_openat(dirfd, pathname, flags, mode);
}

FILE *fopen(const char *restrict pathname, const char *restrict mode) {
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_EXEC_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LOG_DEBUG, "fopen called: filename=%s, mode=%s", pathname, mode);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match;
    ldfl_find_matching_rule("fopen", pathname, op_mask, &return_rule, &return_pcre_match);
    // pcre2_match_data_free(return_pcre_match);

    return real_fopen(pathname, mode);
}

FILE *fopen64(const char *filename, const char *mode) {
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_EXEC_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LOG_DEBUG, "fopen64 called: filename=%s, mode=%s", filename, mode);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match;
    ldfl_find_matching_rule("fopen64", filename, op_mask, &return_rule, &return_pcre_match);
    // pcre2_match_data_free(return_pcre_match);

    return real_fopen64(filename, mode);
}

int open(const char *pathname, int flags, mode_t mode) {
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_EXEC_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LOG_DEBUG, "open called: pathname=%s, flags=%d, mode=%o", pathname, flags, mode);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match;
    ldfl_find_matching_rule("open", pathname, op_mask, &return_rule, &return_pcre_match);
    // pcre2_match_data_free(return_pcre_match);

    return real_open(pathname, flags, mode);
}

int open64(const char *pathname, int flags, mode_t mode) {
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_EXEC_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LOG_DEBUG, "open64 called: pathname=%s, flags=%d, mode=%o", pathname, flags, mode);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match;
    ldfl_find_matching_rule("open64", pathname, op_mask, &return_rule, &return_pcre_match);
    // pcre2_match_data_free(return_pcre_match);

    return real_open64(pathname, flags, mode);
}

int openat64(int dirfd, const char *pathname, int flags, mode_t mode) {
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_EXEC_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LOG_DEBUG, "openat64 called: dirfd=%d, pathname=%s, flags=%d, mode=%o", dirfd, pathname, flags,
                        mode);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match;
    ldfl_find_matching_rule("openat64", pathname, op_mask, &return_rule, &return_pcre_match);
    // pcre2_match_data_free(return_pcre_match);

    return real_openat64(dirfd, pathname, flags, mode);
}

int rename(const char *oldpath, const char *newpath) {
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_EXEC_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LOG_DEBUG, "rename called: oldpath=%s, newpath=%s", oldpath, newpath);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match;
    ldfl_find_matching_rule("rename", oldpath, op_mask, &return_rule, &return_pcre_match);
    // pcre2_match_data_free(return_pcre_match);
    // TODO newpath
    return real_rename(oldpath, newpath);
}

int renameat2(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags) {
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_EXEC_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    REAL(renameat2);
    ldfl_setting.logger(LOG_DEBUG, "renameat2 called: olddirfd=%d, oldpath=%s, newdirfd=%d, newpath=%s, flags=%u",
                        olddirfd, oldpath, newdirfd, newpath, flags);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match;
    ldfl_find_matching_rule("olddirfd", oldpath, op_mask, &return_rule, &return_pcre_match);
    // pcre2_match_data_free(return_pcre_match);
    // TODO newpath

    return real_renameat2(olddirfd, oldpath, newdirfd, newpath, flags);
}

int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath) {
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_EXEC_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LOG_DEBUG, "renameat called: olddirfd=%d, oldpath=%s, newdirfd=%d, newpath=%s", olddirfd,
                        oldpath, newdirfd, newpath);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match;
    ldfl_find_matching_rule("renameat", oldpath, op_mask, &return_rule, &return_pcre_match);
    // pcre2_match_data_free(return_pcre_match);
    // TODO newpath

    return real_renameat(olddirfd, oldpath, newdirfd, newpath);
}

int unlink(const char *pathname) {
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_EXEC_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LOG_DEBUG, "unlink called: pathname=%s", pathname);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match;
    ldfl_find_matching_rule("unlink", pathname, op_mask, &return_rule, &return_pcre_match);
    // pcre2_match_data_free(return_pcre_match);

    return real_unlink(pathname);
}

int unlinkat(int dirfd, const char *pathname, int flags) {
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_EXEC_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LOG_DEBUG, "unlinkat called: dirfd=%d, pathname=%s, flags=%d", dirfd, pathname, flags);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match;
    ldfl_find_matching_rule("unlinkat", pathname, op_mask, &return_rule, &return_pcre_match);
    // pcre2_match_data_free(return_pcre_match);

    return real_unlinkat(dirfd, pathname, flags);
}

int utimes(const char *filename, const struct timeval times[2]) {
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_EXEC_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LOG_DEBUG, "utimes called: filename=%s, times=[%ld, %ld]", filename,
                        (times == NULL) ? 0 : times[0].tv_sec, (times == NULL) ? 0 : times[1].tv_sec);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match;
    ldfl_find_matching_rule("utimes", filename, op_mask, &return_rule, &return_pcre_match);
    // pcre2_match_data_free(return_pcre_match);

    return real_utimes(filename, times);
}

int access(const char *pathname, int mode) {
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_EXEC_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LOG_DEBUG, "access called: pathname=%s, mode=%d", pathname, mode);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match;
    ldfl_find_matching_rule("access", pathname, op_mask, &return_rule, &return_pcre_match);
    // pcre2_match_data_free(return_pcre_match);

    return real_access(pathname, mode);
}

int fstatat(int dirfd, const char *pathname, struct stat *statbuf, int flags) {
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_EXEC_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LOG_DEBUG, "fstatat called: dirfd=%d, pathname=%s, flags=%d", dirfd, pathname, flags);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match;
    ldfl_find_matching_rule("fstatat", pathname, op_mask, &return_rule, &return_pcre_match);
    // pcre2_match_data_free(return_pcre_match);

    return real_fstatat(dirfd, pathname, statbuf, flags);
}

int __xstat(int version, const char *filename, struct stat *statbuf) {
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_EXEC_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LOG_DEBUG, "__xstat called: version=%d, filename=%s", version, filename);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match;
    ldfl_find_matching_rule("__xstat", filename, op_mask, &return_rule, &return_pcre_match);
    // pcre2_match_data_free(return_pcre_match);

    return real___xstat(version, filename, statbuf);
}

int __xstat64(int version, const char *filename, struct stat *statbuf) {
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_EXEC_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LOG_DEBUG, "__xstat64 called: version=%d, filename=%s", version, filename);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match;
    ldfl_find_matching_rule("__xstat64", filename, op_mask, &return_rule, &return_pcre_match);
    // pcre2_match_data_free(return_pcre_match);

    return real___xstat64(version, filename, statbuf);
}

int __lxstat(int version, const char *filename, struct stat *statbuf) {
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_EXEC_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LOG_DEBUG, "__lxstat called: version=%d, filename=%s", version, filename);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match;
    ldfl_find_matching_rule("__lxstat", filename, op_mask, &return_rule, &return_pcre_match);
    // pcre2_match_data_free(return_pcre_match);

    return real___lxstat(version, filename, statbuf);
}

int __fxstatat(int version, int dirfd, const char *pathname, struct stat *statbuf, int flags) {
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_EXEC_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LOG_DEBUG, "__fxstatat called: version=%d, dirfd=%d, pathname=%s, flags=%d", version, dirfd,
                        pathname, flags);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match;
    ldfl_find_matching_rule("__fxstatat", pathname, op_mask, &return_rule, &return_pcre_match);
    // pcre2_match_data_free(return_pcre_match);

    return real___fxstatat(version, dirfd, pathname, statbuf, flags);
}

int utimensat(int dirfd, const char *pathname, const struct timespec times[2], int flags) {
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_EXEC_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LOG_DEBUG, "utimensat called: dirfd=%d, pathname=%s, times=[%ld, %ld], flags=%d", dirfd,
                        pathname, (times == NULL) ? 0 : times[0].tv_sec, (times == NULL) ? 0 : times[1].tv_sec, flags);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match;
    ldfl_find_matching_rule("utimensat", pathname, op_mask, &return_rule, &return_pcre_match);
    // pcre2_match_data_free(return_pcre_match);

    return real_utimensat(dirfd, pathname, times, flags);
}

int execve(const char *filename, char *const argv[], char *const envp[]) {
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_EXEC_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    char *argv_str = ldfl_render_nullable_array(argv);
    char *envp_str = ldfl_render_nullable_array(envp);
    ldfl_setting.logger(LOG_DEBUG, "execve called: filename=%s, argv=%s, envp=%s", filename, argv_str, envp_str);
    free(argv_str);
    free(envp_str);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match;
    ldfl_find_matching_rule("execve", filename, op_mask, &return_rule, &return_pcre_match);
    // pcre2_match_data_free(return_pcre_match);
    // TODO argv[0]

    return real_execve(filename, argv, envp);
}

int execl(const char *path, const char *arg, ...) {
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_EXEC_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    va_list args;
    va_start(args, arg);
    ldfl_setting.logger(LOG_DEBUG, "execl called: path=%s, arg=%s", path, arg);
    va_end(args);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match;
    ldfl_find_matching_rule("execl", path, op_mask, &return_rule, &return_pcre_match);
    // pcre2_match_data_free(return_pcre_match);
    // TODO argv[0]

    return real_execl(path, arg);
}

int execlp(const char *file, const char *arg, ...) {
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_EXEC_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    va_list args;
    va_start(args, arg);
    ldfl_setting.logger(LOG_DEBUG, "execlp called: file=%s, arg=%s", file, arg);
    va_end(args);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match;
    ldfl_find_matching_rule("execlp", file, op_mask, &return_rule, &return_pcre_match);
    // pcre2_match_data_free(return_pcre_match);
    // TODO argv[0]

    return real_execlp(file, arg);
}

int execv(const char *path, char *const argv[]) {
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_EXEC_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    char *argv_str = ldfl_render_nullable_array(argv);
    ldfl_setting.logger(LOG_DEBUG, "execv called: path=%s, argv=%s", path, argv_str);
    free(argv_str);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match;
    ldfl_find_matching_rule("execv", path, op_mask, &return_rule, &return_pcre_match);
    // pcre2_match_data_free(return_pcre_match);
    // TODO argv[0]

    return real_execv(path, argv);
}

int execvp(const char *file, char *const argv[]) {
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_EXEC_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    char *argv_str = ldfl_render_nullable_array(argv);
    ldfl_setting.logger(LOG_DEBUG, "execvp called: file=%s, argv=%s", file, argv_str);
    free(argv_str);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match;
    ldfl_find_matching_rule("execvp", file, op_mask, &return_rule, &return_pcre_match);
    // pcre2_match_data_free(return_pcre_match);
    // TODO argv[0]

    return real_execvp(file, argv);
}

DIR *opendir(const char *name) {
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_EXEC_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LOG_DEBUG, "opendir called: name=%s", name);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match;
    ldfl_find_matching_rule("opendir", name, op_mask, &return_rule, &return_pcre_match);
    // pcre2_match_data_free(return_pcre_match);

    return real_opendir(name);
}

int mkdir(const char *pathname, mode_t mode) {
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_EXEC_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LOG_DEBUG, "mkdir called: pathname=%s, mode=%o", pathname, mode);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match;
    ldfl_find_matching_rule("mkdir", pathname, op_mask, &return_rule, &return_pcre_match);
    // pcre2_match_data_free(return_pcre_match);

    return real_mkdir(pathname, mode);
}

int mkdirat(int dirfd, const char *pathname, mode_t mode) {
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_EXEC_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LOG_DEBUG, "mkdirat called: dirfd=%d, pathname=%s, mode=%o", dirfd, pathname, mode);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match;
    ldfl_find_matching_rule("mkdirat", pathname, op_mask, &return_rule, &return_pcre_match);
    // pcre2_match_data_free(return_pcre_match);

    return real_mkdirat(dirfd, pathname, mode);
}

int rmdir(const char *pathname) {
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_EXEC_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LOG_DEBUG, "rmdir called: pathname=%s", pathname);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match;
    ldfl_find_matching_rule("rmdir", pathname, op_mask, &return_rule, &return_pcre_match);
    // pcre2_match_data_free(return_pcre_match);

    return real_rmdir(pathname);
}

int chdir(const char *path) {
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_EXEC_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LOG_DEBUG, "chdir called: path=%s", path);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match;
    ldfl_find_matching_rule("chdir", path, op_mask, &return_rule, &return_pcre_match);
    // pcre2_match_data_free(return_pcre_match);

    return real_chdir(path);
}

int symlink(const char *target, const char *linkpath) {
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_EXEC_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LOG_DEBUG, "symlink called: target=%s, linkpath=%s", target, linkpath);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match;
    ldfl_find_matching_rule("symlink", linkpath, op_mask, &return_rule, &return_pcre_match);
    // pcre2_match_data_free(return_pcre_match);
    // TODO target

    return real_symlink(target, linkpath);
}

ssize_t readlink(const char *pathname, char *buf, size_t bufsiz) {
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_EXEC_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LOG_DEBUG, "readlink called: pathname=%s, bufsiz=%zu", pathname, bufsiz);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match;
    ldfl_find_matching_rule("readlink", pathname, op_mask, &return_rule, &return_pcre_match);
    // pcre2_match_data_free(return_pcre_match);

    return real_readlink(pathname, buf, bufsiz);
}

int link(const char *oldpath, const char *newpath) {
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_EXEC_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LOG_DEBUG, "link called: oldpath=%s, newpath=%s", oldpath, newpath);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match;
    ldfl_find_matching_rule("link", oldpath, op_mask, &return_rule, &return_pcre_match);
    // pcre2_match_data_free(return_pcre_match);
    // TODO newpath

    return real_link(oldpath, newpath);
}

int linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags) {
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_EXEC_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LOG_DEBUG, "linkat called: olddirfd=%d, oldpath=%s, newdirfd=%d, newpath=%s, flags=%d",
                        olddirfd, oldpath, newdirfd, newpath, flags);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match;
    ldfl_find_matching_rule("linkat", oldpath, op_mask, &return_rule, &return_pcre_match);
    // pcre2_match_data_free(return_pcre_match);
    // TODO newpath

    return real_linkat(olddirfd, oldpath, newdirfd, newpath, flags);
}

int chmod(const char *path, mode_t mode) {
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_EXEC_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LOG_DEBUG, "chmod called: path=%s, mode=%o", path, mode);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match;
    ldfl_find_matching_rule("chmod", path, op_mask, &return_rule, &return_pcre_match);
    // pcre2_match_data_free(return_pcre_match);

    return real_chmod(path, mode);
}

int truncate(const char *path, off_t length) {
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_EXEC_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LOG_DEBUG, "truncate called: path=%s, length=%ld", path, length);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match;
    ldfl_find_matching_rule("truncate", path, op_mask, &return_rule, &return_pcre_match);
    // pcre2_match_data_free(return_pcre_match);

    return real_truncate(path, length);
}

int faccessat(int dirfd, const char *pathname, int mode, int flags) {
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_EXEC_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LOG_DEBUG, "faccessat called: dirfd=%d, pathname=%s, mode=%d, flags=%d", dirfd, pathname, mode,
                        flags);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match;
    ldfl_find_matching_rule("faccessat", pathname, op_mask, &return_rule, &return_pcre_match);
    // pcre2_match_data_free(return_pcre_match);

    return real_faccessat(dirfd, pathname, mode, flags);
}

int stat(const char *pathname, struct stat *statbuf) {
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_EXEC_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LOG_DEBUG, "stat called: pathname=%s", pathname);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match;
    ldfl_find_matching_rule("stat", pathname, op_mask, &return_rule, &return_pcre_match);
    // pcre2_match_data_free(return_pcre_match);

    return real_stat(pathname, statbuf);
}

int lstat(const char *pathname, struct stat *statbuf) {
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_EXEC_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LOG_DEBUG, "lstat called: pathname=%s", pathname);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match;
    ldfl_find_matching_rule("lstat", pathname, op_mask, &return_rule, &return_pcre_match);
    // pcre2_match_data_free(return_pcre_match);

    return real_lstat(pathname, statbuf);
}

int lchown(const char *pathname, uid_t owner, gid_t group) {
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_EXEC_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;

    ldfl_setting.logger(LOG_DEBUG, "lchown called: pathname=%s, owner=%d, group=%d", pathname, owner, group);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match;
    ldfl_find_matching_rule("lchown", pathname, op_mask, &return_rule, &return_pcre_match);
    // pcre2_match_data_free(return_pcre_match);

    return real_lchown(pathname, owner, group);
}

int chown(const char *pathname, uid_t owner, gid_t group) {
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_EXEC_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;

    ldfl_setting.logger(LOG_DEBUG, "chown called: pathname=%s, owner=%d, group=%d", pathname, owner, group);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match;
    ldfl_find_matching_rule("chown", pathname, op_mask, &return_rule, &return_pcre_match);
    // pcre2_match_data_free(return_pcre_match);

    return real_chown(pathname, owner, group);
}

int fchmodat(int dirfd, const char *pathname, mode_t mode, int flags) {
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_EXEC_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;

    ldfl_setting.logger(LOG_DEBUG, "fchmodat called: dirfd=%d, pathname=%s, mode=%o, flags=%d", dirfd, pathname, mode,
                        flags);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match;
    ldfl_find_matching_rule("fchmodat", pathname, op_mask, &return_rule, &return_pcre_match);
    // pcre2_match_data_free(return_pcre_match);

    return real_fchmodat(dirfd, pathname, mode, flags);
}

int symlinkat(const char *target, int newdirfd, const char *linkpath) {
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_EXEC_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;

    ldfl_setting.logger(LOG_DEBUG, "symlinkat called: target=%s, newdirfd=%d, linkpath=%s", target, newdirfd, linkpath);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match;
    ldfl_find_matching_rule("symlinkat", linkpath, op_mask, &return_rule, &return_pcre_match);
    // pcre2_match_data_free(return_pcre_match);

    return real_symlinkat(target, newdirfd, linkpath);
}

int mkfifo(const char *pathname, mode_t mode) {
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_EXEC_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;

    ldfl_setting.logger(LOG_DEBUG, "mkfifo called: pathname=%s, mode=%o", pathname, mode);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match;
    ldfl_find_matching_rule("mkfifo", pathname, op_mask, &return_rule, &return_pcre_match);
    // pcre2_match_data_free(return_pcre_match);

    return real_mkfifo(pathname, mode);
}

int mkfifoat(int dirfd, const char *pathname, mode_t mode) {
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_EXEC_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;

    ldfl_setting.logger(LOG_DEBUG, "mkfifoat called: dirfd=%d, pathname=%s, mode=%o", dirfd, pathname, mode);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match;
    ldfl_find_matching_rule("mkfifoat", pathname, op_mask, &return_rule, &return_pcre_match);
    // pcre2_match_data_free(return_pcre_match);

    return real_mkfifoat(dirfd, pathname, mode);
}

int mknodat(int dirfd, const char *pathname, mode_t mode, dev_t dev) {
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_EXEC_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;

    ldfl_setting.logger(LOG_DEBUG, "mknodat called: dirfd=%d, pathname=%s, mode=%o, dev=%lu", dirfd, pathname, mode,
                        (unsigned long)dev);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match;
    ldfl_find_matching_rule("mknodat", pathname, op_mask, &return_rule, &return_pcre_match);
    // pcre2_match_data_free(return_pcre_match);

    return real_mknodat(dirfd, pathname, mode, dev);
}

int mknod(const char *pathname, mode_t mode, dev_t dev) {
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_EXEC_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;

    ldfl_setting.logger(LOG_DEBUG, "mknod called: pathname=%s, mode=%o, dev=%lu", pathname, mode, (unsigned long)dev);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match;
    ldfl_find_matching_rule("mknod", pathname, op_mask, &return_rule, &return_pcre_match);
    // pcre2_match_data_free(return_pcre_match);

    return real_mknod(pathname, mode, dev);
}

int statx(int dirfd, const char *restrict pathname, int flags, unsigned int mask, struct statx *restrict statxbuf) {
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_EXEC_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;

    ldfl_setting.logger(LOG_DEBUG, "statx called: dirfd=%d, pathname=%s, flags=%d, mask=%u", dirfd, pathname, flags,
                        mask);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match;
    ldfl_find_matching_rule("statx", pathname, op_mask, &return_rule, &return_pcre_match);
    // pcre2_match_data_free(return_pcre_match);

    return real_statx(dirfd, pathname, flags, mask, statxbuf);
}

int creat(const char *pathname, mode_t mode) {
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_EXEC_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;

    ldfl_setting.logger(LOG_DEBUG, "creat called: pathname=%s, mode=%o", pathname, mode);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match;
    ldfl_find_matching_rule("creat", pathname, op_mask, &return_rule, &return_pcre_match);
    // pcre2_match_data_free(return_pcre_match);

    return real_creat(pathname, mode);
}

// No path on this one, maybe we would do something in the futur if we were to track file descriptor
// int fstat(int fd, struct stat *statbuf) {
//    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_EXEC_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC |
//    LDFL_OP_PERM | LDFL_OP_DENY; ldfl_setting.logger(LOG_DEBUG, "fstat called: fd=%d", fd); RINIT; return
//    real_fstat(fd, statbuf);
//}

// No path, maybe lie about the return value(s)?
// char *getcwd(char *buf, size_t size) {
//     uint64_t op_mask =
//         LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_EXEC_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM |
//         LDFL_OP_DENY;
//     ldfl_setting.logger(LOG_DEBUG, "getcwd called: size=%zu", size);
//     RINIT;
//     return real_getcwd(buf, size);
// }

// No path on this one, maybe we would do something in the futur if we were to track file descriptor
// int futimes(int fd, const struct timeval times[2]) {
//    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_EXEC_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC |
//    LDFL_OP_PERM | LDFL_OP_DENY; ldfl_setting.logger(LOG_DEBUG, "futimes called: fd=%d, times=[%ld, %ld]", (times ==
//    NULL) ? 0 : times[0].tv_sec,
//                        (times == NULL) ? 0 : times[1].tv_sec);
//    RINIT;
//    return real_futimes(fd, times);
//}

// int fchmod(int fd, mode_t mode) {
//     uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
//     ldfl_setting.logger(LOG_DEBUG, "fchmod called: fd=%d, mode=%o", fd, mode);
//     RINIT;
//     compiled_mapping_t return_rule;
//     pcre2_match_data *return_pcre_match;
//     ldfl_find_matching_rule("fchmod", NULL, op_mask, &return_rule, &return_pcre_match);
//     // pcre2_match_data_free(return_pcre_match);
//
//     return real_fchmod(fd, mode);
// }

// No path on this one, maybe we would do something in the futur if we were to track file descriptor
// off_t lseek(int fd, off_t offset, int whence) {
//    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_EXEC_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC |
//    LDFL_OP_PERM | LDFL_OP_DENY; ldfl_setting.logger(LOG_DEBUG, "lseek called: fd=%d, offset=%ld, whence=%d", fd,
//    offset, whence); RINIT; return real_lseek(fd, offset, whence);
//}

// No path on this one, maybe we would do something in the futur if we were to track file descriptor
// int ftruncate(int fd, off_t length) {
//    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_EXEC_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC |
//    LDFL_OP_PERM | LDFL_OP_DENY; ldfl_setting.logger(LOG_DEBUG, "ftruncate called: fd=%d, length=%ld", fd, length);
//    RINIT;
//
//    return real_ftruncate(fd, length);
//}

// No path on this one, maybe we would do something in the futur if we were to track file descriptor
// int fchmod(int fd, mode_t mode) {
//    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_EXEC_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC |
//    LDFL_OP_PERM | LDFL_OP_DENY; ldfl_setting.logger(LOG_DEBUG, "fchmod called: fd=%d, mode=%o", fd, mode); RINIT;
//
//    return real_fchmod(fd, mode);
//}

// No path on this one, maybe we would do something in the futur if we were to track file descriptor
// int fchdir(int fd) {
//    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_EXEC_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC |
//    LDFL_OP_PERM | LDFL_OP_DENY; ldfl_setting.logger(LOG_DEBUG, "fchdir called: fd=%d", fd); RINIT;
//	compiled_mapping_t return_rule;
//	pcre2_match_data *return_pcre_match;
//	ldfl_find_matching_rule("renameatx_np", oldpath, op_mask, &return_rule, &return_pcre_match);
//    // pcre2_match_data_free(return_pcre_match);
//
//    return real_fchdir(fd);
//}

// No path on this one, maybe we would do something in the futur if we were to track file descriptor
// DIR *fdopendir(int fd) {
//    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_EXEC_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC |
//    LDFL_OP_PERM | LDFL_OP_DENY; ldfl_setting.logger(LOG_DEBUG, "fdopendir called: fd=%d", fd); RINIT; return
//    real_fdopendir(fd);
//}

// No path on this one, maybe we would do something in the futur if we were to track file descriptor
// int futimens(int fd, const struct timespec times[2]) {
//     uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_EXEC_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC |
//     LDFL_OP_PERM | LDFL_OP_DENY; ldfl_setting.logger(LOG_DEBUG, "futimens called: fd=%d, times=[%ld, %ld]", fd,
//                         (times == NULL) ? 0 : times[0].tv_sec, (times == NULL) ? 0 : times[1].tv_sec);
//     RINIT;
//     return real_futimens(fd, times);
// }

// No path on this one, maybe we would do something in the futur if we were to track file descriptor
// int __fxstat(int version, int fd, struct stat *statbuf) {
//    uint64_t op_mask = LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_EXEC_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC |
//    LDFL_OP_PERM | LDFL_OP_DENY; ldfl_setting.logger(LOG_DEBUG, "__fxstat called: version=%d, fd=%d", version, fd);
//    RINIT; return real___fxstat(version, fd, statbuf);
//}

#if defined(__APPLE__)
int renamex_np(const char *oldpath, const char *newpath, int flags) {
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_EXEC_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LOG_DEBUG, "renamex_np called: oldpath=%s, newpath=%s, flags=%d", oldpath, newpath, flags);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match;
    ldfl_find_matching_rule("renamex_np", oldpath, op_mask, &return_rule, &return_pcre_match);
    // pcre2_match_data_free(return_pcre_match);
    // TODO newpath

    return real_renamex_np(oldpath, newpath, flags);
}

int renameatx_np(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags) {
    uint64_t op_mask =
        LDFL_OP_NOOP | LDFL_OP_MAP | LDFL_OP_EXEC_MAP | LDFL_OP_MEM_OPEN | LDFL_OP_STATIC | LDFL_OP_PERM | LDFL_OP_DENY;
    ldfl_setting.logger(LOG_DEBUG, "renameatx_np called: olddirfd=%d, oldpath=%s, newdirfd=%d, newpath=%s, flags=%d",
                        olddirfd, oldpath, newdirfd, newpath, flags);
    RINIT;
    compiled_mapping_t return_rule;
    pcre2_match_data  *return_pcre_match;
    ldfl_find_matching_rule("renameatx_np", oldpath, op_mask, &return_rule, &return_pcre_match);
    // pcre2_match_data_free(return_pcre_match);
    // TODO newpath
    //
    return real_renameatx_np(olddirfd, oldpath, newdirfd, newpath, flags);
}
#endif

#endif
