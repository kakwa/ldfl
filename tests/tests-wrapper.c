#define _DEFAULT_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#define _BSD_SOURCE
#define _GNU_SOURCE
#define _XOPEN_SOURCE 700

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <argp.h>
#include <fcntl.h>
#include <sys/stat.h>
#define LDLF_TESTING
#include "../ldfl-wrapper.c" // We still need this for now since the functions aren't in a header

// Test suite initialization
int init_suite(void) {
    return 0;
}

int clean_suite(void) {
    return 0;
}

// Helper function to create a temporary file
char *create_temp_file(const char *content) {
    char *path = strdup("/tmp/ldfl-test-XXXXXX");
    int   fd   = mkstemp(path);
    if (fd == -1) {
        free(path);
        return NULL;
    }

    if (content) {
        write(fd, content, strlen(content));
    }

    close(fd);
    return path;
}

// Test cases for argument parsing
void test_parse_arguments(void) {
    struct arguments args   = {0};
    char            *argv[] = {"ldfl-wrapper", "-c", "test.conf", "--", "ls", "-l", NULL};
    int              argc   = 6;

    // Parse arguments
    argp_parse(&argp, argc, argv, 0, 0, &args);

    // Verify parsed arguments
    CU_ASSERT_STRING_EQUAL(args.config_file, "test.conf");
    CU_ASSERT(args.command_argc == 2);
    CU_ASSERT_STRING_EQUAL(args.command_args[0], "ls");
    CU_ASSERT_STRING_EQUAL(args.command_args[1], "-l");
    free(args.command_args);
}

void test_debug_flag(void) {
    struct arguments args   = {0};
    char            *argv[] = {"ldfl-wrapper", "-d", "-c", "test.conf", "--", "ls", NULL};
    int              argc   = 6;

    // Parse arguments
    argp_parse(&argp, argc, argv, 0, 0, &args);

    // Verify debug flag
    CU_ASSERT(args.debug == true);
    free(args.command_args);
}

void test_library_path(void) {
    struct arguments args   = {0};
    char            *argv[] = {"ldfl-wrapper", "-c", "test.conf", "-l", "custom_lib.so", "--", "ls", NULL};
    int              argc   = 7;

    // Parse arguments
    argp_parse(&argp, argc, argv, 0, 0, &args);

    // Verify library path
    CU_ASSERT_STRING_EQUAL(args.library_path, "custom_lib.so");
    free(args.command_args);
}

void test_validate_arguments(void) {
    struct arguments args = {0};

    // Test missing config file
    CU_ASSERT_EQUAL(validate_arguments(&args), 1);

    // Test missing command
    args.config_file = "test.conf";
    CU_ASSERT_EQUAL(validate_arguments(&args), 1);

    // Test valid arguments
    args.command_args    = calloc(2, sizeof(char *));
    args.command_args[0] = "ls";
    args.command_argc    = 1;
    CU_ASSERT_EQUAL(validate_arguments(&args), 0);

    free(args.command_args);
}

void test_setup_environment_success(void) {
    struct arguments args             = {0};
    char            *abs_config_path  = NULL;
    char            *abs_library_path = NULL;

    // Create temporary config file
    char *config_path = create_temp_file("test config");
    CU_ASSERT_PTR_NOT_NULL(config_path);

    // Create temporary library file
    char *lib_path = create_temp_file(NULL);
    CU_ASSERT_PTR_NOT_NULL(lib_path);

    // Setup test arguments
    args.config_file  = config_path;
    args.library_path = lib_path;
    args.debug        = true;

    // Test setup_environment
    int result = setup_environment(&args, &abs_config_path, &abs_library_path);
    CU_ASSERT_EQUAL(result, 0);
    CU_ASSERT_PTR_NOT_NULL(abs_config_path);
    CU_ASSERT_PTR_NOT_NULL(abs_library_path);

    // Cleanup
    free(abs_config_path);
    free(abs_library_path);
    unlink(config_path);
    unlink(lib_path);
    free(config_path);
    free(lib_path);
}

void test_setup_environment_invalid_config(void) {
    struct arguments args             = {0};
    char            *abs_config_path  = NULL;
    char            *abs_library_path = NULL;

    // Create temporary library file
    char *lib_path = create_temp_file(NULL);
    CU_ASSERT_PTR_NOT_NULL(lib_path);

    // Setup test arguments with non-existent config file
    args.config_file  = "/nonexistent/config/file";
    args.library_path = lib_path;

    // Test setup_environment
    int result = setup_environment(&args, &abs_config_path, &abs_library_path);
    CU_ASSERT_EQUAL(result, 1);
    CU_ASSERT_PTR_NULL(abs_config_path);
    CU_ASSERT_PTR_NULL(abs_library_path);

    // Cleanup
    unlink(lib_path);
    free(lib_path);
}

void test_setup_environment_invalid_library(void) {
    struct arguments args             = {0};
    char            *abs_config_path  = NULL;
    char            *abs_library_path = NULL;

    // Create temporary config file
    char *config_path = create_temp_file("test config");
    CU_ASSERT_PTR_NOT_NULL(config_path);

    // Setup test arguments with non-existent library
    args.config_file  = config_path;
    args.library_path = "/nonexistent/library/file";

    // Test setup_environment
    int result = setup_environment(&args, &abs_config_path, &abs_library_path);
    CU_ASSERT_EQUAL(result, 1);
    // Don't check abs_config_path and abs_library_path as they are freed by setup_environment on error

    // Cleanup
    unlink(config_path);
    free(config_path);
}

void test_setup_environment_default_library(void) {
    struct arguments args             = {0};
    char            *abs_config_path  = NULL;
    char            *abs_library_path = NULL;

    // Create temporary config file
    char *config_path = create_temp_file("test config");
    CU_ASSERT_PTR_NOT_NULL(config_path);

    // Create temporary library file in current directory
    char *lib_path = strdup("./libldfl.so");
    int   fd       = open(lib_path, O_CREAT | O_WRONLY, 0644);
    CU_ASSERT_NOT_EQUAL(fd, -1);
    close(fd);

    // Setup test arguments with NULL library path
    args.config_file  = config_path;
    args.library_path = NULL;

    // Test setup_environment
    int result = setup_environment(&args, &abs_config_path, &abs_library_path);
    CU_ASSERT_EQUAL(result, 0);
    CU_ASSERT_PTR_NOT_NULL(abs_config_path);
    CU_ASSERT_PTR_NOT_NULL(abs_library_path);
    CU_ASSERT_STRING_EQUAL(args.library_path, "./libldfl.so");

    // Cleanup
    free(abs_config_path);
    free(abs_library_path);
    unlink(config_path);
    unlink(lib_path);
    free(config_path);
    free(lib_path);
}

// Main test runner
int main() {
    CU_pSuite pSuite = NULL;

    // Initialize CUnit test registry
    if (CUE_SUCCESS != CU_initialize_registry())
        return CU_get_error();

    // Add a suite to the registry
    pSuite = CU_add_suite("ldfl-wrapper_suite", init_suite, clean_suite);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    // Add the tests to the suite
    if ((NULL == CU_add_test(pSuite, "test_parse_arguments", test_parse_arguments)) ||
        (NULL == CU_add_test(pSuite, "test_debug_flag", test_debug_flag)) ||
        (NULL == CU_add_test(pSuite, "test_library_path", test_library_path)) ||
        (NULL == CU_add_test(pSuite, "test_validate_arguments", test_validate_arguments)) ||
        (NULL == CU_add_test(pSuite, "test_setup_environment_success", test_setup_environment_success)) ||
        (NULL == CU_add_test(pSuite, "test_setup_environment_invalid_config", test_setup_environment_invalid_config)) ||
        (NULL ==
         CU_add_test(pSuite, "test_setup_environment_invalid_library", test_setup_environment_invalid_library)) ||
        (NULL ==
         CU_add_test(pSuite, "test_setup_environment_default_library", test_setup_environment_default_library))) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    // Run all tests using the basic interface
    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    CU_cleanup_registry();
    return CU_get_error();
}
