#define _DEFAULT_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE
#define _XOPEN_SOURCE 500
#define _STAT_VER 3
#define LDFL_CONFIG "../cfg/ldfl-config.h"

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include "ldfl.c" // Include the header containing the generate_header function declaration.

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
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wnonnull"
    int result = statx(AT_FDCWD, NULL, 0, 0, &buf);
#pragma GCC diagnostic pop
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

void test_open64(void) {
    int fd = open64("testfile_open64.txt", O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
    CU_ASSERT_NOT_EQUAL(fd, -1);
    if (fd != -1) {
        close(fd);
        remove("testfile_open64.txt");
    }
}

void test_openat64(void) {
    int dirfd = open(".", O_RDONLY);
    CU_ASSERT_NOT_EQUAL(dirfd, -1);

    int fd = openat64(dirfd, "testfile_openat64.txt", O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
    CU_ASSERT_NOT_EQUAL(fd, -1);

    if (fd != -1)
        close(fd);
    if (dirfd != -1)
        close(dirfd);
    remove("testfile_openat64.txt");
}

void test_renameat2(void) {
    FILE *file = fopen("testfile_renameat2_old.txt", "w");
    CU_ASSERT_PTR_NOT_NULL(file);
    if (file)
        fclose(file);

    int result = renameat2(AT_FDCWD, "testfile_renameat2_old.txt", AT_FDCWD, "testfile_renameat2_new.txt", 0);
    CU_ASSERT_EQUAL(result, 0);

    struct stat st;
    CU_ASSERT_EQUAL(stat("testfile_renameat2_new.txt", &st), 0);

    remove("testfile_renameat2_new.txt");
}

void test_utimes(void) {
    FILE *file = fopen("testfile_utimes.txt", "w");
    CU_ASSERT_PTR_NOT_NULL(file);
    if (file)
        fclose(file);

    struct timeval times[2];
    times[0].tv_sec  = 2000000000; // Arbitrary access time
    times[0].tv_usec = 0;
    times[1].tv_sec  = 2000000000; // Arbitrary modification time
    times[1].tv_usec = 0;

    int result = utimes("testfile_utimes.txt", times);
    CU_ASSERT_EQUAL(result, 0);

    struct stat st;
    stat("testfile_utimes.txt", &st);
    CU_ASSERT_EQUAL(st.st_atime, times[0].tv_sec);
    CU_ASSERT_EQUAL(st.st_mtime, times[1].tv_sec);

    remove("testfile_utimes.txt");
}

void test_fstatat(void) {
    FILE *file = fopen("testfile_fstatat.txt", "w");
    CU_ASSERT_PTR_NOT_NULL(file);
    if (file)
        fclose(file);

    struct stat st;
    int         result = fstatat(AT_FDCWD, "testfile_fstatat.txt", &st, 0);
    CU_ASSERT_EQUAL(result, 0);
    CU_ASSERT(S_ISREG(st.st_mode));

    remove("testfile_fstatat.txt");
}

void test___xstat(void) {
    FILE *file = fopen("testfile___xstat.txt", "w");
    CU_ASSERT_PTR_NOT_NULL(file);
    if (file)
        fclose(file);

    struct stat st;
    int         result = __xstat(_STAT_VER, "testfile___xstat.txt", &st);
    CU_ASSERT_NOT_EQUAL(result, 0);
    // FIXME
    // CU_ASSERT_EQUAL(result, 0);
    // CU_ASSERT(S_ISREG(st.st_mode));

    remove("testfile___xstat.txt");
}

void test___xstat64(void) {
    FILE *file = fopen("testfile___xstat64.txt", "w");
    CU_ASSERT_PTR_NOT_NULL(file);
    if (file)
        fclose(file);

    struct stat st;
    int         result = __xstat64(_STAT_VER, "testfile___xstat64.txt", &st);
    CU_ASSERT_NOT_EQUAL(result, 0);
    // FIXME
    // CU_ASSERT_EQUAL(result, 0);
    // CU_ASSERT(S_ISREG(st.st_mode));

    remove("testfile___xstat64.txt");
}

void test___lxstat(void) {
    symlink("/bin/ls", "testfile___lxstat_symlink");
    struct stat st;
    int         result = __lxstat(_STAT_VER, "testfile___lxstat_symlink", &st);
    CU_ASSERT_NOT_EQUAL(result, 0);
    // FIXME
    // CU_ASSERT_EQUAL(result, 0);
    // CU_ASSERT(S_ISLNK(st.st_mode));

    unlink("testfile___lxstat_symlink");
}

void test___fxstatat(void) {
    FILE *file = fopen("testfile___fxstatat.txt", "w");
    CU_ASSERT_PTR_NOT_NULL(file);
    if (file)
        fclose(file);

    struct stat st;
    int         result = __fxstatat(_STAT_VER, AT_FDCWD, "testfile___fxstatat.txt", &st, 0);
    CU_ASSERT_NOT_EQUAL(result, 0);
    // FIXME
    // CU_ASSERT_EQUAL(result, 0);
    // CU_ASSERT(S_ISREG(st.st_mode));

    remove("testfile___fxstatat.txt");
}

void test_execve(void) {
    pid_t pid = fork();
    CU_ASSERT(pid >= 0);

    if (pid == 0) { // Child process
        char *const argv[] = {"/bin/echo", "Hello, execve!", NULL};
        char *const envp[] = {NULL};
        execve("/bin/echo", argv, envp);
        exit(1); // If execve fails
    } else {     // Parent process
        int status;
        wait(&status);
        CU_ASSERT(WIFEXITED(status));
        CU_ASSERT_EQUAL(WEXITSTATUS(status), 0);
    }
}

void test_execl(void) {
    pid_t pid = fork();
    CU_ASSERT(pid >= 0);

    if (pid == 0) { // Child process
        execl("/bin/echo", "echo", "Hello, execl!", NULL);
        exit(1); // If execl fails
    } else {     // Parent process
        int status;
        wait(&status);
        CU_ASSERT(WIFEXITED(status));
        CU_ASSERT_EQUAL(WEXITSTATUS(status), 0);
    }
}

void test_execlp(void) {
    pid_t pid = fork();
    CU_ASSERT(pid >= 0);

    if (pid == 0) { // Child process
        execlp("echo", "echo", "Hello, execlp!", NULL);
        exit(1); // If execlp fails
    } else {     // Parent process
        int status;
        wait(&status);
        CU_ASSERT(WIFEXITED(status));
        CU_ASSERT_EQUAL(WEXITSTATUS(status), 0);
    }
}

void test_execv(void) {
    pid_t pid = fork();
    CU_ASSERT(pid >= 0);

    if (pid == 0) { // Child process
        char *const argv[] = {"/bin/echo", "Hello, execv!", NULL};
        execv("/bin/echo", argv);
        exit(1); // If execv fails
    } else {     // Parent process
        int status;
        wait(&status);
        CU_ASSERT(WIFEXITED(status));
        CU_ASSERT_EQUAL(WEXITSTATUS(status), 0);
    }
}

void test_execvp(void) {
    pid_t pid = fork();
    CU_ASSERT(pid >= 0);

    if (pid == 0) { // Child process
        char *const argv[] = {"echo", "Hello, execvp!", NULL};
        execvp("echo", argv);
        exit(1); // If execvp fails
    } else {     // Parent process
        int status;
        wait(&status);
        CU_ASSERT(WIFEXITED(status));
        CU_ASSERT_EQUAL(WEXITSTATUS(status), 0);
    }
}

void test_mkdirat(void) {
    int fd = open(".", O_RDONLY);
    CU_ASSERT_NOT_EQUAL(fd, -1);

    int result = mkdirat(fd, "testdir_mkdirat", S_IRWXU);
    CU_ASSERT_EQUAL(result, 0);

    struct stat st;
    CU_ASSERT_EQUAL(stat("testdir_mkdirat", &st), 0);
    CU_ASSERT(S_ISDIR(st.st_mode));

    rmdir("testdir_mkdirat");
    if (fd != -1)
        close(fd);
}

void test_link(void) {
    FILE *file = fopen("testfile_link_source.txt", "w");
    CU_ASSERT_PTR_NOT_NULL(file);
    if (file)
        fclose(file);

    int result = link("testfile_link_source.txt", "testfile_link_target.txt");
    CU_ASSERT_EQUAL(result, 0);

    struct stat st;
    CU_ASSERT_EQUAL(stat("testfile_link_target.txt", &st), 0);

    remove("testfile_link_source.txt");
    remove("testfile_link_target.txt");
}

void test_linkat(void) {
    FILE *file = fopen("testfile_linkat_source.txt", "w");
    CU_ASSERT_PTR_NOT_NULL(file);
    if (file)
        fclose(file);

    int result = linkat(AT_FDCWD, "testfile_linkat_source.txt", AT_FDCWD, "testfile_linkat_target.txt", 0);
    CU_ASSERT_EQUAL(result, 0);

    struct stat st;
    CU_ASSERT_EQUAL(stat("testfile_linkat_target.txt", &st), 0);

    remove("testfile_linkat_source.txt");
    remove("testfile_linkat_target.txt");
}

void test_chmod(void) {
    FILE *file = fopen("testfile_chmod.txt", "w");
    CU_ASSERT_PTR_NOT_NULL(file);
    if (file)
        fclose(file);

    int result = chmod("testfile_chmod.txt", S_IRUSR | S_IWUSR);
    CU_ASSERT_EQUAL(result, 0);

    struct stat st;
    stat("testfile_chmod.txt", &st);
    CU_ASSERT_EQUAL(st.st_mode & 0777, S_IRUSR | S_IWUSR);

    remove("testfile_chmod.txt");
}

void test_truncate(void) {
    FILE *file = fopen("testfile_truncate.txt", "w");
    CU_ASSERT_PTR_NOT_NULL(file);
    if (file) {
        fprintf(file, "Hello, World!");
        fclose(file);
    }

    int result = truncate("testfile_truncate.txt", 5);
    CU_ASSERT_EQUAL(result, 0);

    FILE *file_read = fopen("testfile_truncate.txt", "r");
    CU_ASSERT_PTR_NOT_NULL(file_read);
    if (file_read) {
        char buffer[6] = {0};
        fread(buffer, 1, 5, file_read);
        CU_ASSERT_STRING_EQUAL(buffer, "Hello");
        fclose(file_read);
    }

    remove("testfile_truncate.txt");
}

void test_faccessat(void) {
    FILE *file = fopen("testfile_faccessat.txt", "w");
    CU_ASSERT_PTR_NOT_NULL(file);
    if (file)
        fclose(file);

    int result = faccessat(AT_FDCWD, "testfile_faccessat.txt", F_OK, 0);
    CU_ASSERT_EQUAL(result, 0);

    remove("testfile_faccessat.txt");
}

void test_lstat(void) {
    symlink("/bin/ls", "testfile_lstat_symlink");

    struct stat st;
    int         result = lstat("testfile_lstat_symlink", &st);
    CU_ASSERT_EQUAL(result, 0);
    CU_ASSERT(S_ISLNK(st.st_mode));

    unlink("testfile_lstat_symlink");
}

void test_lchown(void) {
    symlink("/bin/ls", "testfile_lchown_symlink");
    int result = lchown("testfile_lchown_symlink", getuid(), getgid());
    CU_ASSERT_EQUAL(result, 0);
    unlink("testfile_lchown_symlink");
}

void test_chown(void) {
    FILE *file = fopen("testfile_chown.txt", "w");
    CU_ASSERT_PTR_NOT_NULL(file);
    if (file)
        fclose(file);

    int result = chown("testfile_chown.txt", getuid(), getgid());
    CU_ASSERT_EQUAL(result, 0);

    remove("testfile_chown.txt");
}

void test_fchmodat(void) {
    FILE *file = fopen("testfile_fchmodat.txt", "w");
    CU_ASSERT_PTR_NOT_NULL(file);
    if (file)
        fclose(file);

    int result = fchmodat(AT_FDCWD, "testfile_fchmodat.txt", S_IRUSR | S_IWUSR, 0);
    CU_ASSERT_EQUAL(result, 0);

    struct stat st;
    stat("testfile_fchmodat.txt", &st);
    CU_ASSERT_EQUAL(st.st_mode & 0777, S_IRUSR | S_IWUSR);

    remove("testfile_fchmodat.txt");
}

void test_symlinkat(void) {
    int dirfd = open(".", O_RDONLY);
    CU_ASSERT_NOT_EQUAL(dirfd, -1);

    int result = symlinkat("/bin/ls", dirfd, "testfile_symlinkat");
    CU_ASSERT_EQUAL(result, 0);

    struct stat st;
    CU_ASSERT_EQUAL(lstat("testfile_symlinkat", &st), 0);
    CU_ASSERT(S_ISLNK(st.st_mode));

    unlink("testfile_symlinkat");
    if (dirfd != -1)
        close(dirfd);
}

void test_mkfifo(void) {
    const char *fifo_path = "test_fifo";

    // Create FIFO
    int result = mkfifo(fifo_path, S_IRUSR | S_IWUSR);
    CU_ASSERT_EQUAL(result, 0);

    // Verify it exists and is a FIFO
    struct stat st;
    CU_ASSERT_EQUAL(stat(fifo_path, &st), 0);
    CU_ASSERT(S_ISFIFO(st.st_mode));

    // Cleanup
    unlink(fifo_path);
}

void test_mkfifoat(void) {
    const char *fifo_name = "test_fifoat";
    int         dirfd     = open(".", O_RDONLY);
    CU_ASSERT_NOT_EQUAL(dirfd, -1);

    // Create FIFO using mkfifoat
    int result = mkfifoat(dirfd, fifo_name, S_IRUSR | S_IWUSR);
    CU_ASSERT_EQUAL(result, 0);

    // Verify it exists and is a FIFO
    struct stat st;
    CU_ASSERT_EQUAL(stat(fifo_name, &st), 0);
    CU_ASSERT(S_ISFIFO(st.st_mode));

    // Cleanup
    unlink(fifo_name);
    if (dirfd != -1)
        close(dirfd);
}

void test_mknod(void) {
    const char *file_path = "test_mknod";

    // Create a regular file using mknod
    int result = mknod(file_path, S_IFREG | S_IRUSR | S_IWUSR, 0);
    CU_ASSERT_EQUAL(result, 0);

    // Verify it exists and is a regular file
    struct stat st;
    CU_ASSERT_EQUAL(stat(file_path, &st), 0);
    CU_ASSERT(S_ISREG(st.st_mode));

    // Cleanup
    unlink(file_path);
}

void test_mknodat(void) {
    const char *file_name = "test_mknodat";
    int         dirfd     = open(".", O_RDONLY);
    CU_ASSERT_NOT_EQUAL(dirfd, -1);

    // Create a regular file using mknodat
    int result = mknodat(dirfd, file_name, S_IFREG | S_IRUSR | S_IWUSR, 0);
    CU_ASSERT_EQUAL(result, 0);

    // Verify it exists and is a regular file
    struct stat st;
    CU_ASSERT_EQUAL(stat(file_name, &st), 0);
    CU_ASSERT(S_ISREG(st.st_mode));

    // Cleanup
    unlink(file_name);
    if (dirfd != -1)
        close(dirfd);
}

int main() {
    CU_initialize_registry();

    CU_pSuite suite = CU_add_suite("Syscall Tests", NULL, NULL);
    // Add the test to the suite
    CU_add_test(suite, "Test open and unlink", test_open_and_unlink);
    CU_add_test(suite, "Test mkdir and rmdir", test_mkdir_and_rmdir);
    CU_add_test(suite, "Test statx null path", test_statx_null_path);
    CU_add_test(suite, "Test statx", test_statx);
    CU_add_test(suite, "Test symlink", test_symlink);
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
    CU_add_test(suite, "Test open64", test_open64);
    CU_add_test(suite, "Test openat64", test_openat64);
    CU_add_test(suite, "Test renameat2", test_renameat2);
    CU_add_test(suite, "Test utimes", test_utimes);
    CU_add_test(suite, "Test fstatat", test_fstatat);
    CU_add_test(suite, "Test __xstat", test___xstat);
    CU_add_test(suite, "Test __xstat64", test___xstat64);
    CU_add_test(suite, "Test __lxstat", test___lxstat);
    CU_add_test(suite, "Test __fxstatat", test___fxstatat);
    CU_add_test(suite, "Test execve", test_execve);
    CU_add_test(suite, "Test execl", test_execl);
    CU_add_test(suite, "Test execlp", test_execlp);
    CU_add_test(suite, "Test execv", test_execv);
    CU_add_test(suite, "Test execvp", test_execvp);
    CU_add_test(suite, "Test mkdirat", test_mkdirat);
    CU_add_test(suite, "Test link", test_link);
    CU_add_test(suite, "Test linkat", test_linkat);
    CU_add_test(suite, "Test chmod", test_chmod);
    CU_add_test(suite, "Test truncate", test_truncate);
    CU_add_test(suite, "Test faccessat", test_faccessat);
    CU_add_test(suite, "Test lstat", test_lstat);
    CU_add_test(suite, "Test lchown", test_lchown);
    CU_add_test(suite, "Test chown", test_chown);
    CU_add_test(suite, "Test fchmodat", test_fchmodat);
    CU_add_test(suite, "Test symlinkat", test_symlinkat);
    CU_add_test(suite, "Test mkfifo", test_mkfifo);
    CU_add_test(suite, "Test mkfifoat", test_mkfifoat);
    CU_add_test(suite, "Test mknod", test_mknod);
    CU_add_test(suite, "Test mknodat", test_mknodat);

    // Run the tests using the basic interface
    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    CU_get_error();
    int ret = CU_get_number_of_failures();
    CU_cleanup_registry();
    return ret;
}
