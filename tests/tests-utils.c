#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700
#define LDLF_UTILS_TESTING
#define LDFL_CONFIG "test-config.h"
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void vsyslog(int priority, const char *fmt, va_list args);

#include "ldfl.c" // Include the header containing the generate_header function declaration.

// Redirect stderr to a buffer for testing
static char  stderr_buffer[1024];
static FILE *stderr_stream;

// Mock `vsyslog` call for validation
static char syslog_buffer[1024];
static int  syslog_priority;

// Mock syslog implementation
void vsyslog(int priority, const char *fmt, va_list args) {
    syslog_priority = priority;
    vsnprintf(syslog_buffer, sizeof(syslog_buffer), fmt, args);
}

// Mock syslog implementation
void syslog(int priority, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    syslog_priority = priority;
    vsnprintf(syslog_buffer, sizeof(syslog_buffer), fmt, args);
    va_end(args);
}

// Setup function to redirect stderr
static int setup_stderr_redirect(void) {
    memset(stderr_buffer, 0, sizeof(stderr_buffer));
    stderr_stream = fmemopen(stderr_buffer, sizeof(stderr_buffer), "w");
    if (!stderr_stream) {
        return -1;
    }
    stderr = stderr_stream; // Redirect stderr
    return 0;
}

// Teardown function to restore stderr
static int teardown_stderr_redirect(void) {
    fclose(stderr_stream);
    stderr = stderr; // Restore original stderr
    return 0;
}

// Test ldfl_stderr_logger
void test_ldfl_stderr_logger(void) {
    // Set mock ldfl_setting
    ldfl_setting.log_level = LOG_WARNING;

    // Log a message below the level
    ldfl_stderr_logger(LDFL_LOG_ALL, LOG_DEBUG, "This should not appear.");
    fflush(stderr_stream);
    CU_ASSERT_STRING_EQUAL_FATAL(stderr_buffer, ""); // No output expected

    // Log a message at the level
    ldfl_stderr_logger(LDFL_LOG_ALL, LOG_WARNING, "This is a warning: %d", 42);
    fflush(stderr_stream);
    CU_ASSERT_STRING_EQUAL_FATAL(stderr_buffer, "LOG_WARNING:  This is a warning: 42\n");

    // Log a message above the level
    ldfl_stderr_logger(LDFL_LOG_ALL, LOG_ERR, "This is an error!");
    fflush(stderr_stream);
    CU_ASSERT_STRING_EQUAL_FATAL(stderr_buffer + strlen("LOG_WARNING:  This is a warning: 42") + 1,
                                 "LOG_ERR:      This is an error!\n");
}

// Test ldfl_syslog_logger
void test_ldfl_syslog_logger(void) {
    // Replace syslog with mock implementation
    ldfl_setting.log_level = LOG_NOTICE;

    // Log a message below the level
    ldfl_syslog_logger(LDFL_LOG_ALL, LOG_DEBUG, "Debug message");
    CU_ASSERT_STRING_EQUAL_FATAL(syslog_buffer, ""); // No output expected

    // Log a message at the level
    ldfl_syslog_logger(LDFL_LOG_FN_CALL, LOG_NOTICE, "Notice message: %d", 99);
    CU_ASSERT_STRING_EQUAL_FATAL(syslog_buffer, "LDFL_FN_CALL: Notice message: 99");
    CU_ASSERT_EQUAL(syslog_priority, LOG_NOTICE);

    // Log a message above the level
    ldfl_syslog_logger(LDFL_LOG_FN_CALL, LOG_CRIT, "Critical error");
    CU_ASSERT_STRING_EQUAL_FATAL(syslog_buffer, "LDFL_FN_CALL: Critical error");
    CU_ASSERT_EQUAL(syslog_priority, LOG_CRIT);
}

// Test cases for argv/envp renderer
void test_ldfl_render_nullable_array_valid() {
    char *list[] = {"arg1", "arg2", "arg3", NULL};
    char *result = ldfl_render_nullable_array(list);
    CU_ASSERT_PTR_NOT_NULL_FATAL(result);
    CU_ASSERT_STRING_EQUAL_FATAL(result, "[\"arg1\", \"arg2\", \"arg3\"]");
    free(result);
}

void test_ldfl_render_nullable_array_empty() {
    char *list[] = {NULL};
    char *result = ldfl_render_nullable_array(list);
    CU_ASSERT_PTR_NOT_NULL_FATAL(result);
    CU_ASSERT_STRING_EQUAL_FATAL(result, "[]");
    free(result);
}

void test_ldfl_render_nullable_array_null() {
    char **list   = NULL; // Passing a NULL pointer
    char  *result = ldfl_render_nullable_array(list);
    CU_ASSERT_PTR_NOT_NULL_FATAL(result);
    CU_ASSERT_STRING_EQUAL_FATAL(result, "[]");
    free(result);
}

void test_ldfl_render_nullable_array_single_element() {
    char *list[] = {"only_one", NULL};
    char *result = ldfl_render_nullable_array(list);
    CU_ASSERT_PTR_NOT_NULL_FATAL(result);
    CU_ASSERT_STRING_EQUAL_FATAL(result, "[\"only_one\"]");
    free(result);
}

void test_absolute_path(void) {
    const char *path   = "/etc/passwd";
    char       *result = ldfl_fullpath(AT_FDCWD, path);
    CU_ASSERT_PTR_NOT_NULL(result);
    if (result) {
        CU_ASSERT_STRING_EQUAL(result, path);
        free(result);
    }
}

void test_relative_path_with_cwd(void) {
    const char *path = "testfile";
    char        cwd[PATH_MAX];
    CU_ASSERT_PTR_NOT_NULL(getcwd(cwd, sizeof(cwd)));

    char expected[PATH_MAX + 256];
    snprintf(expected, sizeof(expected), "%s/%s", cwd, path);

    char *result = ldfl_fullpath(AT_FDCWD, path);
    CU_ASSERT_PTR_NOT_NULL(result);
    if (result) {
        CU_ASSERT_STRING_EQUAL(result, expected);
        free(result);
    }
}

void test_relative_path_with_fd(void) {
    const char *dir   = "/tmp";
    const char *file  = "testfile";
    int         dirfd = open(dir, O_DIRECTORY);
    CU_ASSERT_TRUE(dirfd >= 0);

    if (dirfd >= 0) {
        char expected[PATH_MAX];
        snprintf(expected, sizeof(expected), "%s/%s", dir, file);

        char *result = ldfl_fullpath(dirfd, file);
        CU_ASSERT_PTR_NOT_NULL(result);
        if (result) {
            CU_ASSERT_STRING_EQUAL(result, expected);
            free(result);
        }

        close(dirfd);
    }
}

void test_null_pathname(void) {
    errno        = 0;
    char *result = ldfl_fullpath(AT_FDCWD, NULL);
    CU_ASSERT_PTR_NULL(result);
    CU_ASSERT_EQUAL(errno, EINVAL);
}

void test_empty_pathname(void) {
    errno        = 0;
    char *result = ldfl_fullpath(AT_FDCWD, "");
    CU_ASSERT_PTR_NULL(result);
    CU_ASSERT_EQUAL(errno, ENOENT);
}

void test_nonexistent_path(void) {
    const char *path   = "/nonexistent/path/to/file";
    char       *result = ldfl_fullpath(AT_FDCWD, path);
    CU_ASSERT_PTR_NULL(result);
    CU_ASSERT_EQUAL(errno, ENOENT);
}

void test_invalid_fd(void) {
    const char *path       = "testfile";
    int         invalid_fd = -1;
    char       *result     = ldfl_fullpath(invalid_fd, path);
    CU_ASSERT_PTR_NULL(result);
    CU_ASSERT_EQUAL(errno, EBADF);
}

void test_long_pathname(void) {
    char long_path[PATH_MAX * 2];
    memset(long_path, 'a', sizeof(long_path) - 1);
    long_path[sizeof(long_path) - 1] = '\0';

    errno        = 0;
    char *result = ldfl_fullpath(AT_FDCWD, long_path);
    CU_ASSERT_PTR_NULL(result);
    CU_ASSERT_EQUAL(errno, ENAMETOOLONG);
}

int main() {
    CU_initialize_registry();
    CU_pSuite suite = CU_add_suite("General", NULL, NULL);
    CU_add_test(suite, "render list valid", test_ldfl_render_nullable_array_valid);
    CU_add_test(suite, "empty list", test_ldfl_render_nullable_array_empty);
    CU_add_test(suite, "null list", test_ldfl_render_nullable_array_null);
    CU_add_test(suite, "single element list", test_ldfl_render_nullable_array_single_element);
    CU_add_test(suite, "test_absolute_path", test_absolute_path);
    // CU_add_test(suite, "test_relative_path_with_cwd", test_relative_path_with_cwd);
    // CU_add_test(suite, "test_relative_path_with_fd", test_relative_path_with_fd);
    CU_add_test(suite, "test_null_pathname", test_null_pathname);
    // CU_add_test(suite, "test_empty_pathname", test_empty_pathname);
    // CU_add_test(suite, "test_nonexistent_path", test_nonexistent_path);
    // CU_add_test(suite, "test_invalid_fd", test_invalid_fd);
    CU_add_test(suite, "test_long_pathname", test_long_pathname);

    suite = CU_add_suite("Logger", setup_stderr_redirect, teardown_stderr_redirect);
    CU_add_test(suite, "logger stderr", test_ldfl_stderr_logger);
    CU_add_test(suite, "logger systlog", test_ldfl_syslog_logger);

    // Run the tests using the basic interface
    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    CU_get_error();
    int ret = CU_get_number_of_failures();
    CU_cleanup_registry();
    return ret;
}
