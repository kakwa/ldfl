#define _DEFAULT_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#define _BSD_SOURCE
#define _GNU_SOURCE
#define _XOPEN_SOURCE 700

#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "ldfl.c"

#define TEST_OUTPUT_FILE "tests/exec_test_output.txt"

#define CU_ASSERT_STRING_CONTAINS(haystack, needle)                                                                    \
    do {                                                                                                               \
        if (strstr(haystack, needle) == NULL) {                                                                        \
            printf("```\n%s\n```\n not found in\n ```\n%s\n```'\n", needle, haystack);                                 \
            CU_FAIL("CU_ASSERT_STRING_CONTAINS failed")                                                                \
        } else {                                                                                                       \
            CU_PASS("CU_ASSERT_STRING_CONTAINS passed");                                                               \
        }                                                                                                              \
    } while (0)

// Helper function to read output from file
static char *read_output_file(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file)
        return NULL;

    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);

    char *content = malloc(size + 1);
    fread(content, 1, size, file);
    content[size] = '\0';

    fclose(file);
    return content;
}

typedef enum { EXECVE, EXECL, EXECLP, EXECV, EXECVP } exec_type_t;

// Helper function to run a test command and capture output
static int run_test_command(exec_type_t type, char **output) {
    printf(">>> %d\n", type);
    int fd = open(TEST_OUTPUT_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd == -1)
        return -1;

    // Redirect stdout to our file
    int saved_stdout = dup(STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    close(fd);

    char *argv[] = {"/bin/dir", NULL};
    char *envp[] = {NULL};

    switch (type) {
    case EXECVE:
        execve("/bin/dir", argv, envp);
        break;
    case EXECL:
        execl("/bin/dir", "/bin/dir", NULL);
        break;
    case EXECLP:
        execlp("/bin/dir", "/bin/dir", NULL);
        break;
    case EXECV:
        execv("/bin/dir", argv);
        break;
    case EXECVP:
        execvp("/bin/dir", argv);
        break;
    }

    // Restore stdout
    dup2(saved_stdout, STDERR_FILENO);
    close(saved_stdout);

    // If we get here, exec failed
    *output = read_output_file(TEST_OUTPUT_FILE);
    unlink(TEST_OUTPUT_FILE);
    return 0;
}

static void test_execve(void) {
    char *output = NULL;

    CU_ASSERT_EQUAL(run_test_command(EXECVE, &output), 0);
    CU_ASSERT_PTR_NOT_NULL(output);
    CU_ASSERT_STRING_CONTAINS(output, "noneexistantexecthere");
    free(output);
}

static void test_execl(void) {
    char *output = NULL;

    CU_ASSERT_EQUAL(run_test_command(EXECL, &output), 0);
    CU_ASSERT_PTR_NOT_NULL(output);
    CU_ASSERT_STRING_CONTAINS(output, "noneexistantexecthere");
    free(output);
}

static void test_execlp(void) {
    char *output = NULL;

    CU_ASSERT_EQUAL(run_test_command(EXECLP, &output), 0);
    CU_ASSERT_PTR_NOT_NULL(output);
    CU_ASSERT_STRING_CONTAINS(output, "noneexistantexecthere");
    free(output);
}

static void test_execv(void) {
    char *output = NULL;

    CU_ASSERT_EQUAL(run_test_command(EXECV, &output), 0);
    CU_ASSERT_PTR_NOT_NULL(output);
    CU_ASSERT_STRING_CONTAINS(output, "noneexistantexecthere");
    free(output);
}

static void test_execvp(void) {
    char *output = NULL;

    CU_ASSERT_EQUAL(run_test_command(EXECVP, &output), 0);
    CU_ASSERT_PTR_NOT_NULL(output);
    CU_ASSERT_STRING_CONTAINS(output, "noneexistantexecthere");
    free(output);
}

int main(void) {
    setenv("LDFL_CONFIG", "./tests/exec-config.json", 1);
    CU_initialize_registry();

    // Add the new test suite
    CU_pSuite pSuite = CU_add_suite("Exec Tests", NULL, NULL);
    CU_add_test(pSuite, "test of execve()", test_execve);
    CU_add_test(pSuite, "test of execl()", test_execl);
    CU_add_test(pSuite, "test of execlp()", test_execlp);
    CU_add_test(pSuite, "test of execv()", test_execv);
    CU_add_test(pSuite, "test of execvp()", test_execvp);

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    CU_get_error();
    int ret = CU_get_number_of_failures();
    CU_cleanup_registry();
    return ret;
}
