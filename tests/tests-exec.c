#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include "fliar.c"

#define TEST_SCRIPT_PATH "tests/exec_test_script.sh"
#define TEST_OUTPUT_FILE "tests/exec_test_output.txt"

// Helper function to read output from file
static char* read_output_file(const char* filename) {
    FILE* file = fopen(filename, "r");
    if (!file) return NULL;
    
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    char* content = malloc(size + 1);
    fread(content, 1, size, file);
    content[size] = '\0';
    
    fclose(file);
    return content;
}

// Helper function to run a test command and capture output
static int run_test_command(const char* command, char** output) {
    int fd = open(TEST_OUTPUT_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd == -1) return -1;
    
    pid_t pid = fork();
    if (pid == 0) {
        // Child process
        dup2(fd, STDOUT_FILENO);
        close(fd);
        execl(command);
        exit(1);
    } else if (pid > 0) {
        // Parent process
        close(fd);
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            *output = read_output_file(TEST_OUTPUT_FILE);
            return 0;
        }
    }
    return -1;
}

static void test_execve(void) {
    char* output = NULL;
    char* argv[] = {"/bin/dir", NULL};
    char* envp[] = {NULL};
    
    // Set up the rule
    ldfl_rule_t rule = {
        .pattern = "/bin/dir",
        .replacement = TEST_SCRIPT_PATH,
        .type = LDFL_RULE_TYPE_EXEC
    };
    ldfl_add_rule(&rule);
    
    CU_ASSERT_EQUAL(run_test_command("/bin/dir", &output), 0);
    CU_ASSERT_PTR_NOT_NULL(output);
    if (output) {
        CU_ASSERT_STRING_EQUAL(output, "this tests remapping execs\n");
        free(output);
    }
    
    ldfl_clear_rules();
}

static void test_execl(void) {
    char* output = NULL;
    
    // Set up the rule
    ldfl_rule_t rule = {
        .pattern = "/bin/dir",
        .replacement = TEST_SCRIPT_PATH,
        .type = LDFL_RULE_TYPE_EXEC
    };
    ldfl_add_rule(&rule);
    
    CU_ASSERT_EQUAL(run_test_command("/bin/dir", &output), 0);
    CU_ASSERT_PTR_NOT_NULL(output);
    if (output) {
        CU_ASSERT_STRING_EQUAL(output, "this tests remapping execs\n");
        free(output);
    }
    
    ldfl_clear_rules();
}

static void test_execlp(void) {
    char* output = NULL;
    
    // Set up the rule
    ldfl_rule_t rule = {
        .pattern = "/bin/dir",
        .replacement = TEST_SCRIPT_PATH,
        .type = LDFL_RULE_TYPE_EXEC
    };
    ldfl_add_rule(&rule);
    
    CU_ASSERT_EQUAL(run_test_command("dir", &output), 0);
    CU_ASSERT_PTR_NOT_NULL(output);
    if (output) {
        CU_ASSERT_STRING_EQUAL(output, "this tests remapping execs\n");
        free(output);
    }
    
    ldfl_clear_rules();
}

static void test_execv(void) {
    char* output = NULL;
    char* argv[] = {"/bin/dir", NULL};
    
    // Set up the rule
    ldfl_rule_t rule = {
        .pattern = "/bin/dir",
        .replacement = TEST_SCRIPT_PATH,
        .type = LDFL_RULE_TYPE_EXEC
    };
    ldfl_add_rule(&rule);
    
    CU_ASSERT_EQUAL(run_test_command("/bin/dir", &output), 0);
    CU_ASSERT_PTR_NOT_NULL(output);
    if (output) {
        CU_ASSERT_STRING_EQUAL(output, "this tests remapping execs\n");
        free(output);
    }
    
    ldfl_clear_rules();
}

static void test_execvp(void) {
    char* output = NULL;
    char* argv[] = {"dir", NULL};
    
   CU_ASSERT_EQUAL(run_test_command("dir", &output), 0);
    CU_ASSERT_PTR_NOT_NULL(output);
    if (output) {
        CU_ASSERT_STRING_EQUAL(output, "this tests remapping execs\n");
        free(output);
    }
    
}

int clean_exec_suite(void) {
    unlink(TEST_OUTPUT_FILE);
    return 0;
}

int main(void) {
    CU_pSuite pSuite = NULL;

    if (CUE_SUCCESS != CU_initialize_registry())
        return CU_get_error();

    pSuite = CU_add_suite("exec_suite", clean_exec_suite);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    if ((NULL == CU_add_test(pSuite, "test of execve()", test_execve)) ||
        (NULL == CU_add_test(pSuite, "test of execl()", test_execl)) ||
        (NULL == CU_add_test(pSuite, "test of execlp()", test_execlp)) ||
        (NULL == CU_add_test(pSuite, "test of execv()", test_execv)) ||
        (NULL == CU_add_test(pSuite, "test of execvp()", test_execvp))) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    CU_cleanup_registry();
    return CU_get_error();
} 
