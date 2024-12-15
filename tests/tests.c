#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 500
#define LDLF_UTILS_TESTING

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "fliar.c" // Include the header containing the generate_header function declaration.
#include "embedder.c"

void test_generate_header() {
    const char *input_file  = "test_input.bin";
    const char *output_file = "test_output.h";
    const char *var_name    = "test_var";

    // Create a test binary file
    FILE *in = fopen(input_file, "wb");
    CU_ASSERT_PTR_NOT_NULL_FATAL(in);

    unsigned char test_data[] = {0xDE, 0xAD, 0xBE, 0xEF};
    fwrite(test_data, sizeof(unsigned char), sizeof(test_data), in);
    fclose(in);

    // Generate the header file
    generate_header(input_file, output_file, var_name);

    // Validate the generated header file
    FILE *out = fopen(output_file, "r");
    CU_ASSERT_PTR_NOT_NULL_FATAL(out);

    char buffer[256];
    int  contains_variable = 0;
    while (fgets(buffer, sizeof(buffer), out)) {
        if (strstr(buffer, "const unsigned char test_var[4] = {")) {
            contains_variable = 1;
            break;
        }
    }
    fclose(out);

    CU_ASSERT(contains_variable);

    // Cleanup
    remove(input_file);
    remove(output_file);
}

// Redirect stderr to a buffer for testing
static char  stderr_buffer[1024];
static FILE *stderr_stream;

// Mock `syslog` call for validation
static char syslog_buffer[1024];
static int  syslog_priority;

// Mock syslog implementation
void syslog(int priority, const char *fmt, ...) {
    syslog_priority = priority;
    va_list args;
    va_start(args, fmt);
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
    ldfl_stderr_logger(LOG_DEBUG, "This should not appear.");
    fflush(stderr_stream);
    CU_ASSERT_STRING_EQUAL(stderr_buffer, ""); // No output expected

    // Log a message at the level
    ldfl_stderr_logger(LOG_WARNING, "This is a warning: %d", 42);
    fflush(stderr_stream);
    CU_ASSERT_STRING_EQUAL(stderr_buffer, "LOG_WARNING: This is a warning: 42\n");

    // Log a message above the level
    ldfl_stderr_logger(LOG_ERR, "This is an error!");
    fflush(stderr_stream);
    CU_ASSERT_STRING_EQUAL(stderr_buffer + strlen("LOG_WARNING: This is a warning: 42") + 1,
                           "LOG_ERR: This is an error!\n");
}

// Test ldfl_syslog_logger
void test_ldfl_syslog_logger(void) {
    // Replace syslog with mock implementation
    ldfl_setting.log_level = LOG_NOTICE;

    // Log a message below the level
    ldfl_syslog_logger(LOG_DEBUG, "Debug message");
    CU_ASSERT_STRING_EQUAL(syslog_buffer, ""); // No output expected

    // Log a message at the level
    ldfl_syslog_logger(LOG_NOTICE, "Notice message: %d", 99);
    CU_ASSERT_STRING_EQUAL(syslog_buffer, "Notice message: 99");
    CU_ASSERT_EQUAL(syslog_priority, LOG_NOTICE);

    // Log a message above the level
    ldfl_syslog_logger(LOG_CRIT, "Critical error");
    CU_ASSERT_STRING_EQUAL(syslog_buffer, "Critical error");
    CU_ASSERT_EQUAL(syslog_priority, LOG_CRIT);
}

// Test cases for argv/envp renderer
void test_ldfl_render_nullable_array_valid() {
    char *list[] = {"arg1", "arg2", "arg3", NULL};
    char *result = ldfl_render_nullable_array(list);
    CU_ASSERT_PTR_NOT_NULL(result);
    CU_ASSERT_STRING_EQUAL(result, "[\"arg1\", \"arg2\", \"arg3\"]");
    free(result);
}

void test_ldfl_render_nullable_array_empty() {
    char *list[] = {NULL};
    char *result = ldfl_render_nullable_array(list);
    CU_ASSERT_PTR_NOT_NULL(result);
    CU_ASSERT_STRING_EQUAL(result, "[]");
    free(result);
}

void test_ldfl_render_nullable_array_null() {
    char **list   = NULL; // Passing a NULL pointer
    char  *result = ldfl_render_nullable_array(list);
    CU_ASSERT_PTR_NOT_NULL(result);
    CU_ASSERT_STRING_EQUAL(result, "[]");
    free(result);
}

void test_ldfl_render_nullable_array_single_element() {
    char *list[] = {"only_one", NULL};
    char *result = ldfl_render_nullable_array(list);
    CU_ASSERT_PTR_NOT_NULL(result);
    CU_ASSERT_STRING_EQUAL(result, "[\"only_one\"]");
    free(result);
}

int main() {
    // Initialize CUnit test registry
    if (CUE_SUCCESS != CU_initialize_registry())
        return CU_get_error();

    CU_pSuite suite = CU_add_suite("General", NULL, NULL);
    if (!suite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    // Add a suite for logger tests
    CU_pSuite loggerSuite = CU_add_suite("Logger", setup_stderr_redirect, teardown_stderr_redirect);
    if (!loggerSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    // Add the test to the suite
    if (!CU_add_test(loggerSuite, "logger stderr", test_ldfl_stderr_logger) ||
        !CU_add_test(loggerSuite, "logger systlog", test_ldfl_syslog_logger) ||
        !CU_add_test(suite, "render list valid", test_ldfl_render_nullable_array_valid) ||
        !CU_add_test(suite, "empty list", test_ldfl_render_nullable_array_empty) ||
        !CU_add_test(suite, "null list", test_ldfl_render_nullable_array_null) ||
        !CU_add_test(suite, "single element list", test_ldfl_render_nullable_array_single_element) ||
        !CU_add_test(suite, "generate header", test_generate_header)) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    // Run the tests using the basic interface
    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    CU_cleanup_registry();

    return CU_get_error();
}
