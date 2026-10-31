#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Test-only interposer. Inert outside one canonical, private fixture root. */
static char database[PATH_MAX], wal[PATH_MAX], control[PATH_MAX], evidence[PATH_MAX];
static int enabled;
static pthread_once_t symbols_once = PTHREAD_ONCE_INIT;
static ssize_t (*real_write)(int, const void *, size_t);
static ssize_t (*real_pwrite)(int, const void *, size_t, off_t);
static ssize_t (*real_pwrite64)(int, const void *, size_t, off64_t);
static int (*real_fsync)(int);
static int (*real_fdatasync)(int);

static void symbols(void) {
    real_write = dlsym(RTLD_NEXT, "write");
    real_pwrite = dlsym(RTLD_NEXT, "pwrite");
    real_pwrite64 = dlsym(RTLD_NEXT, "pwrite64");
    real_fsync = dlsym(RTLD_NEXT, "fsync");
    real_fdatasync = dlsym(RTLD_NEXT, "fdatasync");
}

__attribute__((constructor)) static void initialize(void) {
    const char *root = getenv("DSH_JOURNAL_IO_ROOT");
    char canonical[PATH_MAX];
    struct stat status;
    if (!root || root[0] != '/' || strlen(root) > PATH_MAX - 64 ||
        !realpath(root, canonical) || strcmp(root, canonical) != 0 ||
        lstat(root, &status) != 0 || !S_ISDIR(status.st_mode) ||
        status.st_uid != getuid() || (status.st_mode & 077) != 0) return;
    const char *base = strrchr(root, '/');
    if (!base || strncmp(base + 1, "dsh-journal-io-", 15) != 0) return;
    snprintf(database, sizeof database, "%s/state/commands.sqlite", root);
    snprintf(wal, sizeof wal, "%s/state/commands.sqlite-wal", root);
    snprintf(control, sizeof control, "%s/inject", root);
    snprintf(evidence, sizeof evidence, "%s/faults", root);
    enabled = 1;
}

static int fault(int fd, int syncing) {
    if (!enabled) return 0;
    char link[64], target[PATH_MAX], mode[32];
    snprintf(link, sizeof link, "/proc/self/fd/%d", fd);
    ssize_t length = syscall(SYS_readlink, link, target, sizeof target - 1);
    if (length < 0) return 0;
    target[length] = 0;
    int is_wal = strcmp(target, wal) == 0;
    int is_database = strcmp(target, database) == 0;
    if (!is_wal && !is_database) return 0;
    struct stat target_status;
    if (fstat(fd, &target_status) != 0 || !S_ISREG(target_status.st_mode) ||
        target_status.st_uid != getuid() || target_status.st_nlink != 1 ||
        (target_status.st_mode & 077) != 0) return 0;
    int trigger = syscall(SYS_openat, AT_FDCWD, control, O_RDONLY | O_NOFOLLOW | O_CLOEXEC, 0);
    if (trigger < 0) return 0;
    struct stat status;
    int safe = fstat(trigger, &status) == 0 && S_ISREG(status.st_mode) &&
        status.st_uid == getuid() && status.st_nlink == 1 && (status.st_mode & 077) == 0;
    length = safe ? syscall(SYS_read, trigger, mode, sizeof mode - 1) : -1;
    syscall(SYS_close, trigger);
    if (length < 0) return 0;
    mode[length] = 0;
    int matched = (!syncing && is_wal && strcmp(mode, "write-wal") == 0) ||
        (syncing && is_wal && strcmp(mode, "sync-wal") == 0) ||
        (syncing && is_database && strcmp(mode, "sync-db") == 0);
    if (!matched) return 0;
    int proof = syscall(SYS_openat, AT_FDCWD, evidence,
        O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (proof >= 0) {
        char kind = !syncing ? 'w' : is_wal ? 's' : 'm';
        if (fstat(proof, &status) == 0 && S_ISREG(status.st_mode) &&
            status.st_uid == getuid() && status.st_nlink == 1 &&
            (status.st_mode & 077) == 0) syscall(SYS_write, proof, &kind, 1);
        syscall(SYS_close, proof);
    }
    errno = syncing ? EIO : ENOSPC;
    return 1;
}

ssize_t write(int fd, const void *buffer, size_t count) {
    pthread_once(&symbols_once, symbols);
    if (fault(fd, 0)) return -1;
    return real_write(fd, buffer, count);
}
ssize_t pwrite(int fd, const void *buffer, size_t count, off_t offset) {
    pthread_once(&symbols_once, symbols);
    if (fault(fd, 0)) return -1;
    return real_pwrite(fd, buffer, count, offset);
}
ssize_t pwrite64(int fd, const void *buffer, size_t count, off64_t offset) {
    pthread_once(&symbols_once, symbols);
    if (fault(fd, 0)) return -1;
    return real_pwrite64(fd, buffer, count, offset);
}
int fsync(int fd) {
    pthread_once(&symbols_once, symbols);
    if (fault(fd, 1)) return -1;
    return real_fsync(fd);
}
int fdatasync(int fd) {
    pthread_once(&symbols_once, symbols);
    if (fault(fd, 1)) return -1;
    return real_fdatasync(fd);
}
