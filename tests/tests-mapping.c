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

// Test fopen
void test_fopen(void) {
    FILE *file = fopen("testfile.txt", "w");
    CU_ASSERT_PTR_NOT_NULL(file);
    if (file) {
        fclose(file);
        remove("testfile.txt");
    }
}

// Test fopen64
void test_fopen64(void) {
    FILE *file = fopen64("testfile64.txt", "w");
    CU_ASSERT_PTR_NOT_NULL(file);
    if (file) {
        fclose(file);
        remove("testfile64.txt");
    }
}

// Test creat
void test_creat(void) {
    int fd = creat("testfile_creat.txt", S_IRUSR | S_IWUSR);
    CU_ASSERT_NOT_EQUAL(fd, -1);
    if (fd != -1) {
        close(fd);
        remove("testfile_creat.txt");
    }
}

// Test open
void test_open(void) {
    int fd = open("testfile_open.txt", O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
    CU_ASSERT_NOT_EQUAL(fd, -1);
    if (fd != -1) {
        close(fd);
        remove("testfile_open.txt");
    }
}

// Test unlink
void test_unlink(void) {
    FILE *file = fopen("testfile_unlink.txt", "w");
    if (file)
        fclose(file);
    int result = unlink("testfile_unlink.txt");
    CU_ASSERT_EQUAL(result, 0);
}

// Test mkdir and rmdir
void test_mkdir_rmdir(void) {
    int mkdir_result = mkdir("testdir", S_IRWXU);
    CU_ASSERT_EQUAL(mkdir_result, 0);
    int rmdir_result = rmdir("testdir");
    CU_ASSERT_EQUAL(rmdir_result, 0);
}

// Test chdir
void test_chdir(void) {
    char original_dir[PATH_MAX];
    getcwd(original_dir, PATH_MAX);

    int mkdir_result = mkdir("testdir_chdir", S_IRWXU);
    CU_ASSERT_EQUAL(mkdir_result, 0);

    int chdir_result = chdir("testdir_chdir");
    CU_ASSERT_EQUAL(chdir_result, 0);

    chdir(original_dir); // Return to original directory
    rmdir("testdir_chdir");
}

// Test access
void test_access(void) {
    FILE *file = fopen("testfile_access.txt", "w");
    if (file)
        fclose(file);
    int result = access("testfile_access.txt", F_OK);
    CU_ASSERT_EQUAL(result, 0);
    remove("testfile_access.txt");
}

// Test stat
void test_stat(void) {
    struct stat st;
    FILE       *file = fopen("testfile_stat.txt", "w");
    if (file)
        fclose(file);
    int result = stat("testfile_stat.txt", &st);
    CU_ASSERT_EQUAL(result, 0);
    CU_ASSERT(S_ISREG(st.st_mode));
    remove("testfile_stat.txt");
}

// Test symlink and readlink
void test_symlink_readlink(void) {
    FILE *file = fopen("testfile_symlink.txt", "w");
    if (file)
        fclose(file);

    int symlink_result = symlink("testfile_symlink.txt", "testfile_symlink_link.txt");
    CU_ASSERT_EQUAL(symlink_result, 0);

    char    buf[PATH_MAX];
    ssize_t readlink_result = readlink("testfile_symlink_link.txt", buf, sizeof(buf) - 1);
    CU_ASSERT(readlink_result > 0);
    buf[readlink_result] = '\0';
    CU_ASSERT_STRING_EQUAL(buf, "testfile_symlink.txt");

    unlink("testfile_symlink.txt");
    unlink("testfile_symlink_link.txt");
}

void test_freopen(void) {
    FILE *file = fopen("testfile_freopen.txt", "w");
    CU_ASSERT_PTR_NOT_NULL(file);
    if (file) {
        fprintf(file, "Testing freopen");
        fclose(file);
    }

    file = freopen("testfile_freopen.txt", "r", stdin);
    CU_ASSERT_PTR_NOT_NULL(file);
    if (file) {
        char buffer[50];
        fgets(buffer, sizeof(buffer), stdin);
        CU_ASSERT_STRING_EQUAL(buffer, "Testing freopen");
        fclose(file);
    }
    remove("testfile_freopen.txt");
}

void test_openat(void) {
    int fd = open(".", O_RDONLY); // Open the current directory
    CU_ASSERT_NOT_EQUAL(fd, -1);

    int file_fd = openat(fd, "testfile_openat.txt", O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
    CU_ASSERT_NOT_EQUAL(file_fd, -1);

    if (file_fd != -1)
        close(file_fd);
    if (fd != -1)
        close(fd);
    remove("testfile_openat.txt");
}

void test_rename(void) {
    FILE *file = fopen("testfile_rename_old.txt", "w");
    CU_ASSERT_PTR_NOT_NULL(file);
    if (file)
        fclose(file);

    int result = rename("testfile_rename_old.txt", "testfile_rename_new.txt");
    CU_ASSERT_EQUAL(result, 0);

    struct stat st;
    CU_ASSERT_EQUAL(stat("testfile_rename_new.txt", &st), 0);

    remove("testfile_rename_new.txt");
}

void test_renameat(void) {
    FILE *file = fopen("testfile_renameat_old.txt", "w");
    CU_ASSERT_PTR_NOT_NULL(file);
    if (file)
        fclose(file);

    int result = renameat(AT_FDCWD, "testfile_renameat_old.txt", AT_FDCWD, "testfile_renameat_new.txt");
    CU_ASSERT_EQUAL(result, 0);

    struct stat st;
    CU_ASSERT_EQUAL(stat("testfile_renameat_new.txt", &st), 0);

    remove("testfile_renameat_new.txt");
}

void test_unlinkat(void) {
    FILE *file = fopen("testfile_unlinkat.txt", "w");
    CU_ASSERT_PTR_NOT_NULL(file);
    if (file)
        fclose(file);

    int result = unlinkat(AT_FDCWD, "testfile_unlinkat.txt", 0);
    CU_ASSERT_EQUAL(result, 0);

    struct stat st;
    CU_ASSERT_EQUAL(stat("testfile_unlinkat.txt", &st), -1); // File should no longer exist
}

void test_utime(void) {
    FILE *file = fopen("testfile_utime.txt", "w");
    CU_ASSERT_PTR_NOT_NULL(file);
    if (file)
        fclose(file);

    struct utimbuf new_times;
    new_times.actime  = 1000000000; // Set arbitrary access time
    new_times.modtime = 1000000000; // Set arbitrary modification time

    int result = utime("testfile_utime.txt", &new_times);
    CU_ASSERT_EQUAL(result, 0);

    struct stat st;
    stat("testfile_utime.txt", &st);
    CU_ASSERT_EQUAL(st.st_atime, new_times.actime);
    CU_ASSERT_EQUAL(st.st_mtime, new_times.modtime);

    remove("testfile_utime.txt");
}

void test_utimensat(void) {
    FILE *file = fopen("testfile_utimensat.txt", "w");
    CU_ASSERT_PTR_NOT_NULL(file);
    if (file)
        fclose(file);

    struct timespec times[2];
    times[0].tv_sec  = 2000000000; // Arbitrary access time
    times[0].tv_nsec = 0;
    times[1].tv_sec  = 2000000000; // Arbitrary modification time
    times[1].tv_nsec = 0;

    int result = utimensat(AT_FDCWD, "testfile_utimensat.txt", times, 0);
    CU_ASSERT_EQUAL(result, 0);

    struct stat st;
    stat("testfile_utimensat.txt", &st);
    CU_ASSERT_EQUAL(st.st_atime, times[0].tv_sec);
    CU_ASSERT_EQUAL(st.st_mtime, times[1].tv_sec);

    remove("testfile_utimensat.txt");
}

void test_execvp(void) {
    pid_t pid = fork();
    CU_ASSERT(pid >= 0);

    if (pid == 0) {
        char *const args[] = {"/bin/echo", "Hello, World!", NULL};
        execvp("/bin/echo", args);
        exit(1); // Only reached if execvp fails
    } else {
        int status;
        wait(&status);
        CU_ASSERT(WIFEXITED(status));
        CU_ASSERT_EQUAL(WEXITSTATUS(status), 0);
    }
}

void test_readlink(void) {
    symlink("/bin/ls", "testfile_readlink");
    char    buf[PATH_MAX];
    ssize_t len = readlink("testfile_readlink", buf, sizeof(buf) - 1);
    CU_ASSERT(len > 0);
    buf[len] = '\0';
    CU_ASSERT_STRING_EQUAL(buf, "/bin/ls");

    unlink("testfile_readlink");
}

void test_opendir(void) {
    mkdir("testdir_opendir", S_IRWXU);

    DIR *dir = opendir("testdir_opendir");
    CU_ASSERT_PTR_NOT_NULL(dir);
    if (dir)
        closedir(dir);

    rmdir("testdir_opendir");
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
    CU_add_test(suite, "Test fopen", test_fopen);
    CU_add_test(suite, "Test fopen64", test_fopen64);
    CU_add_test(suite, "Test creat", test_creat);
    CU_add_test(suite, "Test open", test_open);
    CU_add_test(suite, "Test unlink", test_unlink);
    CU_add_test(suite, "Test mkdir and rmdir", test_mkdir_rmdir);
    CU_add_test(suite, "Test chdir", test_chdir);
    CU_add_test(suite, "Test access", test_access);
    CU_add_test(suite, "Test stat", test_stat);
    CU_add_test(suite, "Test symlink and readlink", test_symlink_readlink);
    CU_add_test(suite, "Test freopen", test_freopen);
    CU_add_test(suite, "Test openat", test_openat);
    CU_add_test(suite, "Test rename", test_rename);
    CU_add_test(suite, "Test renameat", test_renameat);
    CU_add_test(suite, "Test unlinkat", test_unlinkat);
    CU_add_test(suite, "Test utime", test_utime);
    CU_add_test(suite, "Test utimensat", test_utimensat);
    CU_add_test(suite, "Test execvp", test_execvp);
    CU_add_test(suite, "Test readlink", test_readlink);
    CU_add_test(suite, "Test opendir", test_opendir);

    // Run the tests using the basic interface
    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    CU_get_error();
    int ret = CU_get_number_of_failures();
    CU_cleanup_registry();
    return ret;
}
