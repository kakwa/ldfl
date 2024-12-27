#define _DEFAULT_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE
#define _XOPEN_SOURCE 500

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "fliar.c" // Include the header containing the generate_header function declaration.

void test_open_and_unlink(void) {
    const char *test_file = "test_file.txt";

    // Create and open a test file
    int fd = open(test_file, O_CREAT | O_RDWR, 0644);
    CU_ASSERT(fd >= 0);
    if (fd >= 0)
        close(fd);

    // Remove the test file
    int ret = unlink(test_file);
    CU_ASSERT_EQUAL(ret, 0);
}

void test_mkdir_and_rmdir(void) {
    const char *test_dir = "test_dir";

    // Create a directory
    int ret = mkdir(test_dir, 0755);
    CU_ASSERT_EQUAL(ret, 0);

    // Remove the directory
    ret = rmdir(test_dir);
    CU_ASSERT_EQUAL(ret, 0);
}

void test_symlink(void) {
    const char *target   = "target.txt";
    const char *linkname = "link.txt";

    // Create a target file
    int fd = open(target, O_CREAT | O_RDWR, 0644);
    CU_ASSERT(fd >= 0);
    if (fd >= 0)
        close(fd);

    // Create a symbolic link
    int ret = symlink(target, linkname);
    CU_ASSERT_EQUAL(ret, 0);

    // Clean up
    unlink(target);
    unlink(linkname);
}

void test_statx(void) {
    struct statx buf;
    int          result = statx(AT_FDCWD, "/tmp", 0, 0, &buf);
    CU_ASSERT_EQUAL(result, 0);
}

void test_statx_null_path(void) {
    struct statx buf;
    int          result = statx(AT_FDCWD, NULL, 0, 0, &buf);
    CU_ASSERT_NOT_EQUAL(result, 0);
}

int main() {
    CU_initialize_registry();

    CU_pSuite suite = CU_add_suite("Syscall Tests", NULL, NULL);
    // Add the test to the suite
    CU_add_test(suite, "test_open_and_unlink", test_open_and_unlink);
    CU_add_test(suite, "test_mkdir_and_rmdir", test_mkdir_and_rmdir);
    CU_add_test(suite, "test_statx_null_path", test_statx_null_path);
    CU_add_test(suite, "test_statx", test_statx);
    CU_add_test(suite, "test_symlink", test_symlink);

    // Run the tests using the basic interface
    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    CU_get_error();
    int ret = CU_get_number_of_failures();
    CU_cleanup_registry();
    return ret;
}
