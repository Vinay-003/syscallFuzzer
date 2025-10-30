/*
 * executor.c - Coverage-Guided Syscall Fuzzer Executor
 * 
 * Features:
 * - KCOV-based code coverage collection
 * - Comprehensive syscall coverage (200+ syscalls)
 * - Robust argument parsing with hex/decimal/octal support
 * - Safety limits to prevent system exhaustion
 * - Clean output format for fuzzer parsing
 * - Proper error handling and reporting
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <fcntl.h>

// ============================================================================
// CONFIGURATION
// ============================================================================

#define MAX_ARGS 6
#define MAX_SYSCALL_NAME 64

// Resource limits
#define MAX_MEMORY_MB 512
#define MAX_CPU_SECONDS 5
#define MAX_FILE_SIZE_MB 100

// KCOV configuration
#define KCOV_COVER_SIZE (256 * 1024)
#define KCOV_TRACE_PC 0

// KCOV ioctl commands
#define KCOV_INIT_TRACE _IOR('c', 1, unsigned long)
#define KCOV_ENABLE _IO('c', 100)
#define KCOV_DISABLE _IO('c', 101)

// Global KCOV state
static int kcov_fd = -1;
static unsigned long *kcov_cover = NULL;
static int kcov_available = 0;

// ============================================================================
// KCOV INITIALIZATION
// ============================================================================

/**
 * Initialize KCOV for code coverage collection
 * 
 * KCOV provides kernel code coverage by tracking which code paths
 * are executed during syscalls. This is essential for coverage-guided fuzzing.
 */
static void init_kcov(void) {
    // Attempt to open KCOV device
    kcov_fd = open("/sys/kernel/debug/kcov", O_RDWR);
    if (kcov_fd == -1) {
        fprintf(stderr, "Warning: Failed to open /sys/kernel/debug/kcov: %s\n", strerror(errno));
        fprintf(stderr, "Coverage tracking will not be available.\n");
        return;
    }
    
    // Initialize KCOV trace buffer
    if (ioctl(kcov_fd, KCOV_INIT_TRACE, KCOV_COVER_SIZE)) {
        fprintf(stderr, "Warning: KCOV_INIT_TRACE ioctl failed: %s\n", strerror(errno));
        close(kcov_fd);
        kcov_fd = -1;
        return;
    }
    
    // Memory map the coverage buffer
    kcov_cover = (unsigned long *)mmap(
        NULL, 
        KCOV_COVER_SIZE * sizeof(unsigned long),
        PROT_READ | PROT_WRITE, 
        MAP_SHARED, 
        kcov_fd, 
        0
    );
    
    if (kcov_cover == MAP_FAILED) {
        fprintf(stderr, "Warning: KCOV mmap failed: %s\n", strerror(errno));
        close(kcov_fd);
        kcov_fd = -1;
        kcov_cover = NULL;
        return;
    }
    
    kcov_available = 1;
    printf("KCOV initialized successfully (buffer size: %d entries).\n", KCOV_COVER_SIZE);
}

/**
 * Enable KCOV coverage collection for the current thread
 */
static inline void kcov_enable(void) {
    if (kcov_fd != -1 && kcov_cover != NULL) {
        // Reset counter before enabling
        __atomic_store_n(&kcov_cover[0], 0, __ATOMIC_RELAXED);
        ioctl(kcov_fd, KCOV_ENABLE, KCOV_TRACE_PC);
    }
}

/**
 * Disable KCOV coverage collection and return count
 * 
 * Returns: Number of unique program counters (PCs) covered
 */
static inline unsigned long kcov_disable(void) {
    unsigned long coverage_count = 0;
    
    if (kcov_fd != -1 && kcov_cover != NULL) {
        ioctl(kcov_fd, KCOV_DISABLE, 0);
        // First element contains the number of PCs covered
        coverage_count = __atomic_load_n(&kcov_cover[0], __ATOMIC_RELAXED);
    }
    
    return coverage_count;
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * Parse argument string to long integer
 * Supports decimal, hexadecimal (0x prefix), and octal (0 prefix)
 */
static long parse_arg(const char *arg) {
    if (!arg || *arg == '\0') 
        return 0;
    
    char *endptr;
    long value = strtol(arg, &endptr, 0);  // Auto-detect base
    
    // If no conversion was performed, return 0
    if (endptr == arg) 
        return 0;
    
    return value;
}

/**
 * Set resource limits to prevent system exhaustion
 */
static void set_safety_limits(void) {
    struct rlimit rlim;
    
    // Limit virtual memory
    rlim.rlim_cur = (rlim_t)MAX_MEMORY_MB * 1024 * 1024;
    rlim.rlim_max = (rlim_t)MAX_MEMORY_MB * 1024 * 1024;
    setrlimit(RLIMIT_AS, &rlim);
    
    // Limit CPU time
    rlim.rlim_cur = MAX_CPU_SECONDS;
    rlim.rlim_max = MAX_CPU_SECONDS;
    setrlimit(RLIMIT_CPU, &rlim);
    
    // Limit file size
    rlim.rlim_cur = (rlim_t)MAX_FILE_SIZE_MB * 1024 * 1024;
    rlim.rlim_max = (rlim_t)MAX_FILE_SIZE_MB * 1024 * 1024;
    setrlimit(RLIMIT_FSIZE, &rlim);
    
    // Disable core dumps
    rlim.rlim_cur = 0;
    rlim.rlim_max = 0;
    setrlimit(RLIMIT_CORE, &rlim);
}

/**
 * Signal handler for timeouts
 */
static void timeout_handler(int signum) {
    (void)signum;
    fprintf(stderr, "Timeout: syscall took too long\n");
    _exit(124);  // Special exit code for timeout
}

// ============================================================================
// SYSCALL NAME TO NUMBER MAPPING (COMPLETE)
// ============================================================================

/**
 * Resolve syscall name to syscall number
 * Supports 200+ Linux syscalls across all categories
 * 
 * Returns: syscall number on success, -1 if unknown
 */
static long resolve_syscall(const char *name) {
    // === Memory Management ===
    if (strcmp(name, "mmap") == 0) return SYS_mmap;
    if (strcmp(name, "munmap") == 0) return SYS_munmap;
    if (strcmp(name, "mprotect") == 0) return SYS_mprotect;
    if (strcmp(name, "brk") == 0) return SYS_brk;
    
#ifdef SYS_mremap
    if (strcmp(name, "mremap") == 0) return SYS_mremap;
#endif
#ifdef SYS_msync
    if (strcmp(name, "msync") == 0) return SYS_msync;
#endif
#ifdef SYS_madvise
    if (strcmp(name, "madvise") == 0) return SYS_madvise;
#endif
#ifdef SYS_mincore
    if (strcmp(name, "mincore") == 0) return SYS_mincore;
#endif
#ifdef SYS_mlock
    if (strcmp(name, "mlock") == 0) return SYS_mlock;
#endif
#ifdef SYS_munlock
    if (strcmp(name, "munlock") == 0) return SYS_munlock;
#endif
#ifdef SYS_mlockall
    if (strcmp(name, "mlockall") == 0) return SYS_mlockall;
#endif
#ifdef SYS_munlockall
    if (strcmp(name, "munlockall") == 0) return SYS_munlockall;
#endif
#ifdef SYS_memfd_create
    if (strcmp(name, "memfd_create") == 0) return SYS_memfd_create;
#endif
#ifdef SYS_membarrier
    if (strcmp(name, "membarrier") == 0) return SYS_membarrier;
#endif

    // === File Operations ===
    if (strcmp(name, "open") == 0) return SYS_open;
    if (strcmp(name, "close") == 0) return SYS_close;
    if (strcmp(name, "read") == 0) return SYS_read;
    if (strcmp(name, "write") == 0) return SYS_write;
    if (strcmp(name, "lseek") == 0) return SYS_lseek;
    if (strcmp(name, "dup") == 0) return SYS_dup;
    if (strcmp(name, "dup2") == 0) return SYS_dup2;
    if (strcmp(name, "pipe") == 0) return SYS_pipe;
    
#ifdef SYS_openat
    if (strcmp(name, "openat") == 0) return SYS_openat;
#endif
#ifdef SYS_readv
    if (strcmp(name, "readv") == 0) return SYS_readv;
#endif
#ifdef SYS_writev
    if (strcmp(name, "writev") == 0) return SYS_writev;
#endif
#ifdef SYS_pread64
    if (strcmp(name, "pread64") == 0) return SYS_pread64;
#endif
#ifdef SYS_pwrite64
    if (strcmp(name, "pwrite64") == 0) return SYS_pwrite64;
#endif
#ifdef SYS_preadv
    if (strcmp(name, "preadv") == 0) return SYS_preadv;
#endif
#ifdef SYS_pwritev
    if (strcmp(name, "pwritev") == 0) return SYS_pwritev;
#endif
#ifdef SYS_dup3
    if (strcmp(name, "dup3") == 0) return SYS_dup3;
#endif
#ifdef SYS_pipe2
    if (strcmp(name, "pipe2") == 0) return SYS_pipe2;
#endif

    // === File Metadata ===
    if (strcmp(name, "stat") == 0) return SYS_stat;
    if (strcmp(name, "fstat") == 0) return SYS_fstat;
    if (strcmp(name, "lstat") == 0) return SYS_lstat;
    
#ifdef SYS_newfstatat
    if (strcmp(name, "fstatat") == 0) return SYS_newfstatat;
#endif
#ifdef SYS_statx
    if (strcmp(name, "statx") == 0) return SYS_statx;
#endif
#ifdef SYS_access
    if (strcmp(name, "access") == 0) return SYS_access;
#endif
#ifdef SYS_faccessat
    if (strcmp(name, "faccessat") == 0) return SYS_faccessat;
#endif
#ifdef SYS_faccessat2
    if (strcmp(name, "faccessat2") == 0) return SYS_faccessat2;
#endif

    // === File Control ===
    if (strcmp(name, "fcntl") == 0) return SYS_fcntl;
    if (strcmp(name, "ioctl") == 0) return SYS_ioctl;
    
#ifdef SYS_flock
    if (strcmp(name, "flock") == 0) return SYS_flock;
#endif
#ifdef SYS_fsync
    if (strcmp(name, "fsync") == 0) return SYS_fsync;
#endif
#ifdef SYS_fdatasync
    if (strcmp(name, "fdatasync") == 0) return SYS_fdatasync;
#endif
#ifdef SYS_sync
    if (strcmp(name, "sync") == 0) return SYS_sync;
#endif
#ifdef SYS_truncate
    if (strcmp(name, "truncate") == 0) return SYS_truncate;
#endif
#ifdef SYS_ftruncate
    if (strcmp(name, "ftruncate") == 0) return SYS_ftruncate;
#endif
#ifdef SYS_fallocate
    if (strcmp(name, "fallocate") == 0) return SYS_fallocate;
#endif
#ifdef SYS_sendfile
    if (strcmp(name, "sendfile") == 0) return SYS_sendfile;
#endif
#ifdef SYS_copy_file_range
    if (strcmp(name, "copy_file_range") == 0) return SYS_copy_file_range;
#endif
#ifdef SYS_splice
    if (strcmp(name, "splice") == 0) return SYS_splice;
#endif
#ifdef SYS_vmsplice
    if (strcmp(name, "vmsplice") == 0) return SYS_vmsplice;
#endif
#ifdef SYS_tee
    if (strcmp(name, "tee") == 0) return SYS_tee;
#endif

    // === Directory Operations ===
#ifdef SYS_getcwd
    if (strcmp(name, "getcwd") == 0) return SYS_getcwd;
#endif
#ifdef SYS_chdir
    if (strcmp(name, "chdir") == 0) return SYS_chdir;
#endif
#ifdef SYS_fchdir
    if (strcmp(name, "fchdir") == 0) return SYS_fchdir;
#endif
#ifdef SYS_chroot
    if (strcmp(name, "chroot") == 0) return SYS_chroot;
#endif
#ifdef SYS_mkdir
    if (strcmp(name, "mkdir") == 0) return SYS_mkdir;
#endif
#ifdef SYS_mkdirat
    if (strcmp(name, "mkdirat") == 0) return SYS_mkdirat;
#endif
#ifdef SYS_rmdir
    if (strcmp(name, "rmdir") == 0) return SYS_rmdir;
#endif
#ifdef SYS_getdents64
    if (strcmp(name, "getdents64") == 0) return SYS_getdents64;
#endif

    // === Link Operations ===
#ifdef SYS_link
    if (strcmp(name, "link") == 0) return SYS_link;
#endif
#ifdef SYS_linkat
    if (strcmp(name, "linkat") == 0) return SYS_linkat;
#endif
#ifdef SYS_symlink
    if (strcmp(name, "symlink") == 0) return SYS_symlink;
#endif
#ifdef SYS_symlinkat
    if (strcmp(name, "symlinkat") == 0) return SYS_symlinkat;
#endif
#ifdef SYS_readlink
    if (strcmp(name, "readlink") == 0) return SYS_readlink;
#endif
#ifdef SYS_readlinkat
    if (strcmp(name, "readlinkat") == 0) return SYS_readlinkat;
#endif
#ifdef SYS_unlink
    if (strcmp(name, "unlink") == 0) return SYS_unlink;
#endif
#ifdef SYS_unlinkat
    if (strcmp(name, "unlinkat") == 0) return SYS_unlinkat;
#endif
#ifdef SYS_rename
    if (strcmp(name, "rename") == 0) return SYS_rename;
#endif
#ifdef SYS_renameat
    if (strcmp(name, "renameat") == 0) return SYS_renameat;
#endif
#ifdef SYS_renameat2
    if (strcmp(name, "renameat2") == 0) return SYS_renameat2;
#endif

    // === Permissions ===
#ifdef SYS_chmod
    if (strcmp(name, "chmod") == 0) return SYS_chmod;
#endif
#ifdef SYS_fchmod
    if (strcmp(name, "fchmod") == 0) return SYS_fchmod;
#endif
#ifdef SYS_fchmodat
    if (strcmp(name, "fchmodat") == 0) return SYS_fchmodat;
#endif
#ifdef SYS_chown
    if (strcmp(name, "chown") == 0) return SYS_chown;
#endif
#ifdef SYS_fchown
    if (strcmp(name, "fchown") == 0) return SYS_fchown;
#endif
#ifdef SYS_fchownat
    if (strcmp(name, "fchownat") == 0) return SYS_fchownat;
#endif
#ifdef SYS_umask
    if (strcmp(name, "umask") == 0) return SYS_umask;
#endif

    // === Extended Attributes ===
#ifdef SYS_setxattr
    if (strcmp(name, "setxattr") == 0) return SYS_setxattr;
#endif
#ifdef SYS_lsetxattr
    if (strcmp(name, "lsetxattr") == 0) return SYS_lsetxattr;
#endif
#ifdef SYS_fsetxattr
    if (strcmp(name, "fsetxattr") == 0) return SYS_fsetxattr;
#endif
#ifdef SYS_getxattr
    if (strcmp(name, "getxattr") == 0) return SYS_getxattr;
#endif
#ifdef SYS_lgetxattr
    if (strcmp(name, "lgetxattr") == 0) return SYS_lgetxattr;
#endif
#ifdef SYS_fgetxattr
    if (strcmp(name, "fgetxattr") == 0) return SYS_fgetxattr;
#endif
#ifdef SYS_listxattr
    if (strcmp(name, "listxattr") == 0) return SYS_listxattr;
#endif
#ifdef SYS_llistxattr
    if (strcmp(name, "llistxattr") == 0) return SYS_llistxattr;
#endif
#ifdef SYS_flistxattr
    if (strcmp(name, "flistxattr") == 0) return SYS_flistxattr;
#endif
#ifdef SYS_removexattr
    if (strcmp(name, "removexattr") == 0) return SYS_removexattr;
#endif
#ifdef SYS_lremovexattr
    if (strcmp(name, "lremovexattr") == 0) return SYS_lremovexattr;
#endif
#ifdef SYS_fremovexattr
    if (strcmp(name, "fremovexattr") == 0) return SYS_fremovexattr;
#endif

    // === Time Operations ===
#ifdef SYS_utime
    if (strcmp(name, "utime") == 0) return SYS_utime;
#endif
#ifdef SYS_utimes
    if (strcmp(name, "utimes") == 0) return SYS_utimes;
#endif
#ifdef SYS_utimensat
    if (strcmp(name, "utimensat") == 0) return SYS_utimensat;
#endif
#ifdef SYS_nanosleep
    if (strcmp(name, "nanosleep") == 0) return SYS_nanosleep;
#endif
#ifdef SYS_clock_gettime
    if (strcmp(name, "clock_gettime") == 0) return SYS_clock_gettime;
#endif
#ifdef SYS_clock_settime
    if (strcmp(name, "clock_settime") == 0) return SYS_clock_settime;
#endif
#ifdef SYS_clock_getres
    if (strcmp(name, "clock_getres") == 0) return SYS_clock_getres;
#endif
#ifdef SYS_clock_nanosleep
    if (strcmp(name, "clock_nanosleep") == 0) return SYS_clock_nanosleep;
#endif
#ifdef SYS_gettimeofday
    if (strcmp(name, "gettimeofday") == 0) return SYS_gettimeofday;
#endif
#ifdef SYS_settimeofday
    if (strcmp(name, "settimeofday") == 0) return SYS_settimeofday;
#endif
#ifdef SYS_times
    if (strcmp(name, "times") == 0) return SYS_times;
#endif

    // === Timers ===
#ifdef SYS_timer_create
    if (strcmp(name, "timer_create") == 0) return SYS_timer_create;
#endif
#ifdef SYS_timer_settime
    if (strcmp(name, "timer_settime") == 0) return SYS_timer_settime;
#endif
#ifdef SYS_timer_gettime
    if (strcmp(name, "timer_gettime") == 0) return SYS_timer_gettime;
#endif
#ifdef SYS_timer_getoverrun
    if (strcmp(name, "timer_getoverrun") == 0) return SYS_timer_getoverrun;
#endif
#ifdef SYS_timer_delete
    if (strcmp(name, "timer_delete") == 0) return SYS_timer_delete;
#endif
#ifdef SYS_timerfd_create
    if (strcmp(name, "timerfd_create") == 0) return SYS_timerfd_create;
#endif
#ifdef SYS_timerfd_settime
    if (strcmp(name, "timerfd_settime") == 0) return SYS_timerfd_settime;
#endif
#ifdef SYS_timerfd_gettime
    if (strcmp(name, "timerfd_gettime") == 0) return SYS_timerfd_gettime;
#endif

    // === Process Management ===
    if (strcmp(name, "fork") == 0) return SYS_fork;
    if (strcmp(name, "vfork") == 0) return SYS_vfork;
    if (strcmp(name, "clone") == 0) return SYS_clone;
    if (strcmp(name, "execve") == 0) return SYS_execve;
    if (strcmp(name, "exit") == 0) return SYS_exit;
    if (strcmp(name, "wait4") == 0) return SYS_wait4;
    
#ifdef SYS_clone3
    if (strcmp(name, "clone3") == 0) return SYS_clone3;
#endif
#ifdef SYS_execveat
    if (strcmp(name, "execveat") == 0) return SYS_execveat;
#endif
#ifdef SYS_exit_group
    if (strcmp(name, "exit_group") == 0) return SYS_exit_group;
#endif
#ifdef SYS_waitid
    if (strcmp(name, "waitid") == 0) return SYS_waitid;
#endif

    // === Process Info ===
    if (strcmp(name, "getpid") == 0) return SYS_getpid;
    if (strcmp(name, "getppid") == 0) return SYS_getppid;
    if (strcmp(name, "gettid") == 0) return SYS_gettid;
    if (strcmp(name, "getuid") == 0) return SYS_getuid;
    if (strcmp(name, "geteuid") == 0) return SYS_geteuid;
    if (strcmp(name, "getgid") == 0) return SYS_getgid;
    if (strcmp(name, "getegid") == 0) return SYS_getegid;
    
#ifdef SYS_getpgrp
    if (strcmp(name, "getpgrp") == 0) return SYS_getpgrp;
#endif
#ifdef SYS_getpgid
    if (strcmp(name, "getpgid") == 0) return SYS_getpgid;
#endif
#ifdef SYS_getsid
    if (strcmp(name, "getsid") == 0) return SYS_getsid;
#endif
#ifdef SYS_setsid
    if (strcmp(name, "setsid") == 0) return SYS_setsid;
#endif
#ifdef SYS_setpgid
    if (strcmp(name, "setpgid") == 0) return SYS_setpgid;
#endif

    // === Process Credentials ===
    if (strcmp(name, "setuid") == 0) return SYS_setuid;
    if (strcmp(name, "setgid") == 0) return SYS_setgid;
    
#ifdef SYS_setreuid
    if (strcmp(name, "setreuid") == 0) return SYS_setreuid;
#endif
#ifdef SYS_setregid
    if (strcmp(name, "setregid") == 0) return SYS_setregid;
#endif
#ifdef SYS_setresuid
    if (strcmp(name, "setresuid") == 0) return SYS_setresuid;
#endif
#ifdef SYS_setresgid
    if (strcmp(name, "setresgid") == 0) return SYS_setresgid;
#endif
#ifdef SYS_getresuid
    if (strcmp(name, "getresuid") == 0) return SYS_getresuid;
#endif
#ifdef SYS_getresgid
    if (strcmp(name, "getresgid") == 0) return SYS_getresgid;
#endif
#ifdef SYS_getgroups
    if (strcmp(name, "getgroups") == 0) return SYS_getgroups;
#endif
#ifdef SYS_setgroups
    if (strcmp(name, "setgroups") == 0) return SYS_setgroups;
#endif

    // === Process Control ===
#ifdef SYS_prctl
    if (strcmp(name, "prctl") == 0) return SYS_prctl;
#endif
#ifdef SYS_setpriority
    if (strcmp(name, "setpriority") == 0) return SYS_setpriority;
#endif
#ifdef SYS_getpriority
    if (strcmp(name, "getpriority") == 0) return SYS_getpriority;
#endif
#ifdef SYS_nice
    if (strcmp(name, "nice") == 0) return SYS_nice;
#endif
#ifdef SYS_sched_yield
    if (strcmp(name, "sched_yield") == 0) return SYS_sched_yield;
#endif
#ifdef SYS_sched_setscheduler
    if (strcmp(name, "sched_setscheduler") == 0) return SYS_sched_setscheduler;
#endif
#ifdef SYS_sched_getscheduler
    if (strcmp(name, "sched_getscheduler") == 0) return SYS_sched_getscheduler;
#endif
#ifdef SYS_sched_setparam
    if (strcmp(name, "sched_setparam") == 0) return SYS_sched_setparam;
#endif
#ifdef SYS_sched_getparam
    if (strcmp(name, "sched_getparam") == 0) return SYS_sched_getparam;
#endif
#ifdef SYS_sched_setaffinity
    if (strcmp(name, "sched_setaffinity") == 0) return SYS_sched_setaffinity;
#endif
#ifdef SYS_sched_getaffinity
    if (strcmp(name, "sched_getaffinity") == 0) return SYS_sched_getaffinity;
#endif
#ifdef SYS_prlimit64
    if (strcmp(name, "prlimit64") == 0) return SYS_prlimit64;
#endif

    // === Signals ===
    if (strcmp(name, "kill") == 0) return SYS_kill;
    
#ifdef SYS_tkill
    if (strcmp(name, "tkill") == 0) return SYS_tkill;
#endif
#ifdef SYS_tgkill
    if (strcmp(name, "tgkill") == 0) return SYS_tgkill;
#endif
#ifdef SYS_rt_sigaction
    if (strcmp(name, "rt_sigaction") == 0) return SYS_rt_sigaction;
#endif
#ifdef SYS_rt_sigprocmask
    if (strcmp(name, "rt_sigprocmask") == 0) return SYS_rt_sigprocmask;
#endif
#ifdef SYS_rt_sigsuspend
    if (strcmp(name, "rt_sigsuspend") == 0) return SYS_rt_sigsuspend;
#endif
#ifdef SYS_rt_sigqueueinfo
    if (strcmp(name, "rt_sigqueueinfo") == 0) return SYS_rt_sigqueueinfo;
#endif
#ifdef SYS_rt_sigtimedwait
    if (strcmp(name, "rt_sigtimedwait") == 0) return SYS_rt_sigtimedwait;
#endif
#ifdef SYS_sigaltstack
    if (strcmp(name, "sigaltstack") == 0) return SYS_sigaltstack;
#endif
#ifdef SYS_signalfd
    if (strcmp(name, "signalfd") == 0) return SYS_signalfd;
#endif
#ifdef SYS_signalfd4
    if (strcmp(name, "signalfd4") == 0) return SYS_signalfd4;
#endif

    // === Networking - Sockets ===
    if (strcmp(name, "socket") == 0) return SYS_socket;
    
#ifdef SYS_socketpair
    if (strcmp(name, "socketpair") == 0) return SYS_socketpair;
#endif
#ifdef SYS_connect
    if (strcmp(name, "connect") == 0) return SYS_connect;
#endif
#ifdef SYS_bind
    if (strcmp(name, "bind") == 0) return SYS_bind;
#endif
#ifdef SYS_listen
    if (strcmp(name, "listen") == 0) return SYS_listen;
#endif
#ifdef SYS_accept
    if (strcmp(name, "accept") == 0) return SYS_accept;
#endif
#ifdef SYS_accept4
    if (strcmp(name, "accept4") == 0) return SYS_accept4;
#endif
#ifdef SYS_getsockname
    if (strcmp(name, "getsockname") == 0) return SYS_getsockname;
#endif
#ifdef SYS_getpeername
    if (strcmp(name, "getpeername") == 0) return SYS_getpeername;
#endif
#ifdef SYS_shutdown
    if (strcmp(name, "shutdown") == 0) return SYS_shutdown;
#endif

    // === Networking - I/O ===
#ifdef SYS_sendto
    if (strcmp(name, "sendto") == 0) return SYS_sendto;
#endif
#ifdef SYS_recvfrom
    if (strcmp(name, "recvfrom") == 0) return SYS_recvfrom;
#endif
#ifdef SYS_sendmsg
    if (strcmp(name, "sendmsg") == 0) return SYS_sendmsg;
#endif
#ifdef SYS_recvmsg
    if (strcmp(name, "recvmsg") == 0) return SYS_recvmsg;
#endif
#ifdef SYS_sendmmsg
    if (strcmp(name, "sendmmsg") == 0) return SYS_sendmmsg;
#endif
#ifdef SYS_recvmmsg
    if (strcmp(name, "recvmmsg") == 0) return SYS_recvmmsg;
#endif

    // === Networking - Options ===
#ifdef SYS_setsockopt
    if (strcmp(name, "setsockopt") == 0) return SYS_setsockopt;
#endif
#ifdef SYS_getsockopt
    if (strcmp(name, "getsockopt") == 0) return SYS_getsockopt;
#endif

    // === I/O Multiplexing ===
#ifdef SYS_select
    if (strcmp(name, "select") == 0) return SYS_select;
#endif
#ifdef SYS_pselect6
    if (strcmp(name, "pselect6") == 0) return SYS_pselect6;
#endif
#ifdef SYS_poll
    if (strcmp(name, "poll") == 0) return SYS_poll;
#endif
#ifdef SYS_ppoll
    if (strcmp(name, "ppoll") == 0) return SYS_ppoll;
#endif
#ifdef SYS_epoll_create
    if (strcmp(name, "epoll_create") == 0) return SYS_epoll_create;
#endif
#ifdef SYS_epoll_create1
    if (strcmp(name, "epoll_create1") == 0) return SYS_epoll_create1;
#endif
#ifdef SYS_epoll_ctl
    if (strcmp(name, "epoll_ctl") == 0) return SYS_epoll_ctl;
#endif
#ifdef SYS_epoll_wait
    if (strcmp(name, "epoll_wait") == 0) return SYS_epoll_wait;
#endif
#ifdef SYS_epoll_pwait
    if (strcmp(name, "epoll_pwait") == 0) return SYS_epoll_pwait;
#endif

    // === Event Notification ===
#ifdef SYS_eventfd
    if (strcmp(name, "eventfd") == 0) return SYS_eventfd;
#endif
#ifdef SYS_eventfd2
    if (strcmp(name, "eventfd2") == 0) return SYS_eventfd2;
#endif
#ifdef SYS_inotify_init
    if (strcmp(name, "inotify_init") == 0) return SYS_inotify_init;
#endif
#ifdef SYS_inotify_init1
    if (strcmp(name, "inotify_init1") == 0) return SYS_inotify_init1;
#endif
#ifdef SYS_inotify_add_watch
    if (strcmp(name, "inotify_add_watch") == 0) return SYS_inotify_add_watch;
#endif
#ifdef SYS_inotify_rm_watch
    if (strcmp(name, "inotify_rm_watch") == 0) return SYS_inotify_rm_watch;
#endif
#ifdef SYS_fanotify_init
    if (strcmp(name, "fanotify_init") == 0) return SYS_fanotify_init;
#endif
#ifdef SYS_fanotify_mark
    if (strcmp(name, "fanotify_mark") == 0) return SYS_fanotify_mark;
#endif

    // === Futex ===
#ifdef SYS_futex
    if (strcmp(name, "futex") == 0) return SYS_futex;
#endif
#ifdef SYS_set_robust_list
    if (strcmp(name, "set_robust_list") == 0) return SYS_set_robust_list;
#endif
#ifdef SYS_get_robust_list
    if (strcmp(name, "get_robust_list") == 0) return SYS_get_robust_list;
#endif
#ifdef SYS_set_tid_address
    if (strcmp(name, "set_tid_address") == 0) return SYS_set_tid_address;
#endif

    // === System V IPC ===
#ifdef SYS_shmget
    if (strcmp(name, "shmget") == 0) return SYS_shmget;
#endif
#ifdef SYS_shmat
    if (strcmp(name, "shmat") == 0) return SYS_shmat;
#endif
#ifdef SYS_shmdt
    if (strcmp(name, "shmdt") == 0) return SYS_shmdt;
#endif
#ifdef SYS_shmctl
    if (strcmp(name, "shmctl") == 0) return SYS_shmctl;
#endif
#ifdef SYS_semget
    if (strcmp(name, "semget") == 0) return SYS_semget;
#endif
#ifdef SYS_semop
    if (strcmp(name, "semop") == 0) return SYS_semop;
#endif
#ifdef SYS_semctl
    if (strcmp(name, "semctl") == 0) return SYS_semctl;
#endif
#ifdef SYS_msgget
    if (strcmp(name, "msgget") == 0) return SYS_msgget;
#endif
#ifdef SYS_msgsnd
    if (strcmp(name, "msgsnd") == 0) return SYS_msgsnd;
#endif
#ifdef SYS_msgrcv
    if (strcmp(name, "msgrcv") == 0) return SYS_msgrcv;
#endif
#ifdef SYS_msgctl
    if (strcmp(name, "msgctl") == 0) return SYS_msgctl;
#endif

    // === Special Files ===
#ifdef SYS_mknod
    if (strcmp(name, "mknod") == 0) return SYS_mknod;
#endif
#ifdef SYS_mknodat
    if (strcmp(name, "mknodat") == 0) return SYS_mknodat;
#endif

    // === Advanced/Kernel ===
#ifdef SYS_ptrace
    if (strcmp(name, "ptrace") == 0) return SYS_ptrace;
#endif
#ifdef SYS_bpf
    if (strcmp(name, "bpf") == 0) return SYS_bpf;
#endif
#ifdef SYS_keyctl
    if (strcmp(name, "keyctl") == 0) return SYS_keyctl;
#endif
#ifdef SYS_userfaultfd
    if (strcmp(name, "userfaultfd") == 0) return SYS_userfaultfd;
#endif
#ifdef SYS_seccomp
    if (strcmp(name, "seccomp") == 0) return SYS_seccomp;
#endif
#ifdef SYS_perf_event_open
    if (strcmp(name, "perf_event_open") == 0) return SYS_perf_event_open;
#endif
#ifdef SYS_io_uring_setup
    if (strcmp(name, "io_uring_setup") == 0) return SYS_io_uring_setup;
#endif
#ifdef SYS_io_uring_enter
    if (strcmp(name, "io_uring_enter") == 0) return SYS_io_uring_enter;
#endif
#ifdef SYS_io_uring_register
    if (strcmp(name, "io_uring_register") == 0) return SYS_io_uring_register;
#endif

    // === Namespaces ===
#ifdef SYS_unshare
    if (strcmp(name, "unshare") == 0) return SYS_unshare;
#endif
#ifdef SYS_setns
    if (strcmp(name, "setns") == 0) return SYS_setns;
#endif
#ifdef SYS_kcmp
    if (strcmp(name, "kcmp") == 0) return SYS_kcmp;
#endif
#ifdef SYS_pidfd_open
    if (strcmp(name, "pidfd_open") == 0) return SYS_pidfd_open;
#endif
#ifdef SYS_pidfd_send_signal
    if (strcmp(name, "pidfd_send_signal") == 0) return SYS_pidfd_send_signal;
#endif
#ifdef SYS_pidfd_getfd
    if (strcmp(name, "pidfd_getfd") == 0) return SYS_pidfd_getfd;
#endif

    // === Mount ===
#ifdef SYS_mount
    if (strcmp(name, "mount") == 0) return SYS_mount;
#endif
#ifdef SYS_umount2
    if (strcmp(name, "umount2") == 0) return SYS_umount2;
#endif
#ifdef SYS_pivot_root
    if (strcmp(name, "pivot_root") == 0) return SYS_pivot_root;
#endif

    // === Modules ===
#ifdef SYS_init_module
    if (strcmp(name, "init_module") == 0) return SYS_init_module;
#endif
#ifdef SYS_finit_module
    if (strcmp(name, "finit_module") == 0) return SYS_finit_module;
#endif
#ifdef SYS_delete_module
    if (strcmp(name, "delete_module") == 0) return SYS_delete_module;
#endif

    // === Capabilities ===
#ifdef SYS_capget
    if (strcmp(name, "capget") == 0) return SYS_capget;
#endif
#ifdef SYS_capset
    if (strcmp(name, "capset") == 0) return SYS_capset;
#endif

    // === System Info ===
    if (strcmp(name, "uname") == 0) return SYS_uname;
    
#ifdef SYS_sysinfo
    if (strcmp(name, "sysinfo") == 0) return SYS_sysinfo;
#endif
#ifdef SYS_syslog
    if (strcmp(name, "syslog") == 0) return SYS_syslog;
#endif
#ifdef SYS_getcpu
    if (strcmp(name, "getcpu") == 0) return SYS_getcpu;
#endif
#ifdef SYS_getrandom
    if (strcmp(name, "getrandom") == 0) return SYS_getrandom;
#endif

    // === Misc ===
#ifdef SYS_ioperm
    if (strcmp(name, "ioperm") == 0) return SYS_ioperm;
#endif
#ifdef SYS_iopl
    if (strcmp(name, "iopl") == 0) return SYS_iopl;
#endif
#ifdef SYS_quotactl
    if (strcmp(name, "quotactl") == 0) return SYS_quotactl;
#endif
#ifdef SYS_lookup_dcookie
    if (strcmp(name, "lookup_dcookie") == 0) return SYS_lookup_dcookie;
#endif
#ifdef SYS_name_to_handle_at
    if (strcmp(name, "name_to_handle_at") == 0) return SYS_name_to_handle_at;
#endif
#ifdef SYS_open_by_handle_at
    if (strcmp(name, "open_by_handle_at") == 0) return SYS_open_by_handle_at;
#endif
#ifdef SYS_reboot
    if (strcmp(name, "reboot") == 0) return SYS_reboot;
#endif

    // Syscall not found
    return -1;
}

// ============================================================================
// MAIN EXECUTION
// ============================================================================

int main(int argc, char *argv[]) {
    // Initialize KCOV for coverage tracking
    init_kcov();

    // Validate command-line arguments
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <syscall_name> [arg1] [arg2] ... [arg6]\n", argv[0]);
        return 1;
    }

    const char *syscall_name = argv[1];
    if (strlen(syscall_name) >= MAX_SYSCALL_NAME) {
        fprintf(stderr, "Error: Syscall name too long\n");
        return 1;
    }

    // Resolve syscall name to number
    long syscall_num = resolve_syscall(syscall_name);
    if (syscall_num == -1) {
        fprintf(stderr, "Error: Unknown syscall '%s'\n", syscall_name);
        return 1;
    }

    // Parse arguments (up to MAX_ARGS)
    long args[MAX_ARGS] = {0};
    int num_args = argc - 2;
    if (num_args > MAX_ARGS) num_args = MAX_ARGS;
    
    for (int i = 0; i < num_args; i++) {
        args[i] = parse_arg(argv[i + 2]);
    }

    // Apply safety limits to prevent resource exhaustion
    set_safety_limits();
    
    // Set up timeout handler for long-running syscalls
    signal(SIGALRM, timeout_handler);
    alarm(MAX_CPU_SECONDS);

    // Print what we're about to execute (for logging)
    printf("Fuzzing attempt: %s(", syscall_name);
    for (int i = 0; i < num_args; i++) {
        printf("0x%lx%s", args[i], (i == num_args - 1) ? "" : ", ");
    }
    printf(")\n");
    fflush(stdout);

    // Enable KCOV coverage collection
    kcov_enable();

    // Execute the syscall
    errno = 0;
    long ret = syscall(syscall_num, args[0], args[1], args[2], args[3], args[4], args[5]);
    int saved_errno = errno;

    // Disable KCOV and retrieve coverage count
    unsigned long coverage_count = kcov_disable();

    // Special handling for fork/vfork - child process should exit immediately
    if ((syscall_num == SYS_fork || syscall_num == SYS_vfork) && ret == 0) {
        _exit(0);
    }

    // Cancel the timeout alarm
    alarm(0);

    // Print result in parseable format for the fuzzer
    printf("syscall(%ld) = %ld", syscall_num, ret);
    
    if (ret == -1 && saved_errno != 0) {
        // Syscall failed - include errno for analysis
        printf(" (errno=%d: %s, coverage=%lu)", saved_errno, strerror(saved_errno), coverage_count);
    } else {
        // Syscall succeeded or returned non-error value
        printf(" (coverage=%lu)", coverage_count);
    }
    
    printf("\n");
    fflush(stdout);

    return 0;
}