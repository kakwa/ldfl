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
#include <errno.h>

#include "../lib/ldfl.c"

#define EXEC_TEST_CONFIG "./tests/exec-config.json"

int mock_execve(const char *pathname, char *const argv[], char *const envp[]) {
    printf("mock_execp: %s\n", pathname);
    return 0;
}
int mock_execl(const char *pathname, const char *arg, ...) {
    printf("mock_execl: %s\n", pathname);
    return 0;
}
int mock_execlp(const char *file, const char *arg, ...) {
    printf("mock_execlp: %s\n", file);
    return 0;
}
int mock_execv(const char *pathname, char *const argv[]) {
    printf("mock_execv: %s\n", pathname);
    return 0;
}
int mock_execvp(const char *file, char *const argv[]) {
    printf("mock_execvp: %s\n", file);
    return 0;
}

// Assign mocks to function pointers
void init_mock_exec_functions() {
    ldfl_init();
    real_execve = mock_execve;
    real_execl  = mock_execl;
    real_execlp = mock_execlp;
    real_execv  = mock_execv;
    real_execvp = mock_execvp;
    return;
}

// Test execve function
void test_execve(void) {
    char *argv[] = {"/bin/ls", NULL};
    char *envp[] = {NULL};
    execve("/bin/ls", argv, envp);
    // TODO asserts
}

void test_execve_deny(void) {
    char *argv[] = {"/bin/echo", NULL};
    char *envp[] = {NULL};
    execve("/bin/echo", argv, envp);
    // TODO asserts
}

void test_execve_redir(void) {
    char *argv[] = {"/bin/true", NULL};
    char *envp[] = {NULL};
    execve("/bin/true", argv, envp);
    // TODO asserts
}

// Test execl function
void test_execl(void) {
    // Test redirect
    execl("/bin/ls", "/bin/ls", NULL);
}

// Test execlp function
void test_execlp(void) {
    // Test redirect
    execlp("ls", "ls", NULL);
}

// Test execv function
void test_execv(void) {
    // Test redirect
    char *argv[] = {"/bin/ls", NULL};
    execv("/bin/ls", argv);
}

// Test execvp function
void test_execvp(void) {
    // Test redirect
    char *argv[] = {"ls", NULL};
    execvp("ls", argv);
}

int main(void) {
    setenv("LDFL_CONFIG", EXEC_TEST_CONFIG, 1);
    CU_initialize_registry();
    init_mock_exec_functions();

    // Add the new test suite
    CU_pSuite pSuite = CU_add_suite("Exec Tests", NULL, NULL);
    CU_add_test(pSuite, "test of execve()", test_execve);
    CU_add_test(pSuite, "test of execve() (deny)", test_execve_deny);
    CU_add_test(pSuite, "test of execve() (redir)", test_execve_redir);
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
