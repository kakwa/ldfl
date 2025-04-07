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
#define LDLF_TESTING
#include "../ldfl-wrapper.c"  // We still need this for now since the functions aren't in a header

// Test suite initialization
int init_suite(void) {
    return 0;
}

int clean_suite(void) {
    return 0;
}

// Test cases for argument parsing
void test_parse_arguments(void) {
    struct arguments args = {0};
    char *argv[] = {
        "ldfl-wrapper",
        "-c",
        "test.conf",
        "--",
        "ls",
        "-l",
        NULL
    };
    int argc = 6;

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
    struct arguments args = {0};
    char *argv[] = {
        "ldfl-wrapper",
        "-d",
        "-c",
        "test.conf",
        "--",
        "ls",
        NULL
    };
    int argc = 6;

    // Parse arguments
    argp_parse(&argp, argc, argv, 0, 0, &args);

    // Verify debug flag
    CU_ASSERT(args.debug == true);
    free(args.command_args);
}

void test_library_path(void) {
    struct arguments args = {0};
    char *argv[] = {
        "ldfl-wrapper",
        "-c",
        "test.conf",
        "-l",
        "custom_lib.so",
        "--",
        "ls",
        NULL
    };
    int argc = 7;

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
    args.command_args = calloc(2, sizeof(char *));
    args.command_args[0] = "ls";
    args.command_argc = 1;
    CU_ASSERT_EQUAL(validate_arguments(&args), 0);
    
    free(args.command_args);
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
        (NULL == CU_add_test(pSuite, "test_validate_arguments", test_validate_arguments))) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    // Run all tests using the basic interface
    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    CU_cleanup_registry();
    return CU_get_error();
} 
