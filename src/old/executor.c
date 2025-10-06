// executor.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

// A simple helper to convert string arguments to long integers
static long get_arg(char *arg) {
    // Use strtol to correctly parse hex/decimal/octal numbers from the fuzzer
    return strtol(arg, NULL, 0);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <syscall_name> [args...]\n", argv[0]);
        return 1;
    }

    const char *syscall_name = argv[1];
    long syscall_num = -1;

    // --- Syscall Name to Number Translation ---
    // Baseline from your version (kept unguarded so it compiles as before)
    if (strcmp(syscall_name, "read") == 0) syscall_num = SYS_read;
    else if (strcmp(syscall_name, "write") == 0) syscall_num = SYS_write;
    else if (strcmp(syscall_name, "open") == 0) syscall_num = SYS_open;
    else if (strcmp(syscall_name, "close") == 0) syscall_num = SYS_close;
    else if (strcmp(syscall_name, "stat") == 0) syscall_num = SYS_stat;
    else if (strcmp(syscall_name, "fstat") == 0) syscall_num = SYS_fstat;
    else if (strcmp(syscall_name, "lseek") == 0) syscall_num = SYS_lseek;
    else if (strcmp(syscall_name, "mmap") == 0) syscall_num = SYS_mmap;
    else if (strcmp(syscall_name, "mprotect") == 0) syscall_num = SYS_mprotect;
    else if (strcmp(syscall_name, "munmap") == 0) syscall_num = SYS_munmap;
    else if (strcmp(syscall_name, "brk") == 0) syscall_num = SYS_brk;
    else if (strcmp(syscall_name, "ioctl") == 0) syscall_num = SYS_ioctl;
    else if (strcmp(syscall_name, "pread64") == 0) syscall_num = SYS_pread64;
    else if (strcmp(syscall_name, "pwrite64") == 0) syscall_num = SYS_pwrite64;
    else if (strcmp(syscall_name, "pipe") == 0) syscall_num = SYS_pipe;
    else if (strcmp(syscall_name, "dup") == 0) syscall_num = SYS_dup;
    else if (strcmp(syscall_name, "dup2") == 0) syscall_num = SYS_dup2;
    else if (strcmp(syscall_name, "fork") == 0) syscall_num = SYS_fork;
    else if (strcmp(syscall_name, "vfork") == 0) syscall_num = SYS_vfork;
    else if (strcmp(syscall_name, "clone") == 0) syscall_num = SYS_clone;
    else if (strcmp(syscall_name, "execve") == 0) syscall_num = SYS_execve;
    else if (strcmp(syscall_name, "exit") == 0) syscall_num = SYS_exit;
    else if (strcmp(syscall_name, "wait4") == 0) syscall_num = SYS_wait4;
    else if (strcmp(syscall_name, "kill") == 0) syscall_num = SYS_kill;
    else if (strcmp(syscall_name, "uname") == 0) syscall_num = SYS_uname;
    else if (strcmp(syscall_name, "fcntl") == 0) syscall_num = SYS_fcntl;
    else if (strcmp(syscall_name, "flock") == 0) syscall_num = SYS_flock;
    else if (strcmp(syscall_name, "fsync") == 0) syscall_num = SYS_fsync;
    else if (strcmp(syscall_name, "fdatasync") == 0) syscall_num = SYS_fdatasync;
    else if (strcmp(syscall_name, "truncate") == 0) syscall_num = SYS_truncate;
    else if (strcmp(syscall_name, "ftruncate") == 0) syscall_num = SYS_ftruncate;
    else if (strcmp(syscall_name, "getdents64") == 0) syscall_num = SYS_getdents64;
    else if (strcmp(syscall_name, "getcwd") == 0) syscall_num = SYS_getcwd;
    else if (strcmp(syscall_name, "chdir") == 0) syscall_num = SYS_chdir;
    else if (strcmp(syscall_name, "fchdir") == 0) syscall_num = SYS_fchdir;
    else if (strcmp(syscall_name, "rename") == 0) syscall_num = SYS_rename;
    else if (strcmp(syscall_name, "mkdir") == 0) syscall_num = SYS_mkdir;
    else if (strcmp(syscall_name, "rmdir") == 0) syscall_num = SYS_rmdir;
    else if (strcmp(syscall_name, "unlink") == 0) syscall_num = SYS_unlink;
    else if (strcmp(syscall_name, "chmod") == 0) syscall_num = SYS_chmod;
    else if (strcmp(syscall_name, "fchmod") == 0) syscall_num = SYS_fchmod;
    else if (strcmp(syscall_name, "chown") == 0) syscall_num = SYS_chown;
    else if (strcmp(syscall_name, "fchown") == 0) syscall_num = SYS_fchown;
    else if (strcmp(syscall_name, "getpid") == 0) syscall_num = SYS_getpid;
    else if (strcmp(syscall_name, "getuid") == 0) syscall_num = SYS_getuid;
    else if (strcmp(syscall_name, "getgid") == 0) syscall_num = SYS_getgid;
    else if (strcmp(syscall_name, "setuid") == 0) syscall_num = SYS_setuid;
    else if (strcmp(syscall_name, "setgid") == 0) syscall_num = SYS_setgid;
    else if (strcmp(syscall_name, "gettid") == 0) syscall_num = SYS_gettid;
    else if (strcmp(syscall_name, "tgkill") == 0) syscall_num = SYS_tgkill;
    else if (strcmp(syscall_name, "socket") == 0) syscall_num = SYS_socket;
    else if (strcmp(syscall_name, "connect") == 0) syscall_num = SYS_connect;
    else if (strcmp(syscall_name, "accept") == 0) syscall_num = SYS_accept;
    else if (strcmp(syscall_name, "bind") == 0) syscall_num = SYS_bind;
    else if (strcmp(syscall_name, "listen") == 0) syscall_num = SYS_listen;
    else if (strcmp(syscall_name, "sendto") == 0) syscall_num = SYS_sendto;
    else if (strcmp(syscall_name, "recvfrom") == 0) syscall_num = SYS_recvfrom;
    else if (strcmp(syscall_name, "setsockopt") == 0) syscall_num = SYS_setsockopt;
    else if (strcmp(syscall_name, "getsockopt") == 0) syscall_num = SYS_getsockopt;
    else if (strcmp(syscall_name, "bpf") == 0) syscall_num = SYS_bpf;
    else if (strcmp(syscall_name, "io_uring_setup") == 0) syscall_num = SYS_io_uring_setup;
    else if (strcmp(syscall_name, "keyctl") == 0) syscall_num = SYS_keyctl;
    else if (strcmp(syscall_name, "userfaultfd") == 0) syscall_num = SYS_userfaultfd;
    else if (strcmp(syscall_name, "seccomp") == 0) syscall_num = SYS_seccomp;
    else if (strcmp(syscall_name, "ptrace") == 0) syscall_num = SYS_ptrace;
    else if (strcmp(syscall_name, "mount") == 0) syscall_num = SYS_mount;
    else if (strcmp(syscall_name, "unshare") == 0) syscall_num = SYS_unshare;
    else if (strcmp(syscall_name, "init_module") == 0) syscall_num = SYS_init_module;
    else if (strcmp(syscall_name, "finit_module") == 0) syscall_num = SYS_finit_module;
    else if (strcmp(syscall_name, "capset") == 0) syscall_num = SYS_capset;
    else if (strcmp(syscall_name, "openat") == 0) syscall_num = SYS_openat;
    else if (strcmp(syscall_name, "unlinkat") == 0) syscall_num = SYS_unlinkat;
    else if (strcmp(syscall_name, "renameat") == 0) syscall_num = SYS_renameat;

    // --- Big expansion below (each guarded with #ifdef) ---

    // I/O vectors & polling
#ifdef SYS_readv
    else if (strcmp(syscall_name, "readv") == 0) syscall_num = SYS_readv;
#endif
#ifdef SYS_writev
    else if (strcmp(syscall_name, "writev") == 0) syscall_num = SYS_writev;
#endif
#ifdef SYS_preadv
    else if (strcmp(syscall_name, "preadv") == 0) syscall_num = SYS_preadv;
#endif
#ifdef SYS_pwritev
    else if (strcmp(syscall_name, "pwritev") == 0) syscall_num = SYS_pwritev;
#endif
#ifdef SYS_select
    else if (strcmp(syscall_name, "select") == 0) syscall_num = SYS_select;
#endif
#ifdef SYS_pselect6
    else if (strcmp(syscall_name, "pselect6") == 0) syscall_num = SYS_pselect6;
#endif
#ifdef SYS_poll
    else if (strcmp(syscall_name, "poll") == 0) syscall_num = SYS_poll;
#endif
#ifdef SYS_ppoll
    else if (strcmp(syscall_name, "ppoll") == 0) syscall_num = SYS_ppoll;
#endif
#ifdef SYS_epoll_create1
    else if (strcmp(syscall_name, "epoll_create1") == 0) syscall_num = SYS_epoll_create1;
#endif
#ifdef SYS_epoll_ctl
    else if (strcmp(syscall_name, "epoll_ctl") == 0) syscall_num = SYS_epoll_ctl;
#endif
#ifdef SYS_epoll_wait
    else if (strcmp(syscall_name, "epoll_wait") == 0) syscall_num = SYS_epoll_wait;
#endif
#ifdef SYS_epoll_pwait
    else if (strcmp(syscall_name, "epoll_pwait") == 0) syscall_num = SYS_epoll_pwait;
#endif

    // File & FS operations
#ifdef SYS_sendfile
    else if (strcmp(syscall_name, "sendfile") == 0) syscall_num = SYS_sendfile;
#endif
#ifdef SYS_copy_file_range
    else if (strcmp(syscall_name, "copy_file_range") == 0) syscall_num = SYS_copy_file_range;
#endif
#ifdef SYS_splice
    else if (strcmp(syscall_name, "splice") == 0) syscall_num = SYS_splice;
#endif
#ifdef SYS_vmsplice
    else if (strcmp(syscall_name, "vmsplice") == 0) syscall_num = SYS_vmsplice;
#endif
#ifdef SYS_tee
    else if (strcmp(syscall_name, "tee") == 0) syscall_num = SYS_tee;
#endif
#ifdef SYS_fallocate
    else if (strcmp(syscall_name, "fallocate") == 0) syscall_num = SYS_fallocate;
#endif
#ifdef SYS_posix_fadvise
    else if (strcmp(syscall_name, "posix_fadvise") == 0) syscall_num = SYS_posix_fadvise;
#endif
#ifdef SYS_utime
    else if (strcmp(syscall_name, "utime") == 0) syscall_num = SYS_utime;
#endif
#ifdef SYS_utimes
    else if (strcmp(syscall_name, "utimes") == 0) syscall_num = SYS_utimes;
#endif
#ifdef SYS_utimensat
    else if (strcmp(syscall_name, "utimensat") == 0) syscall_num = SYS_utimensat;
#endif
#ifdef SYS_link
    else if (strcmp(syscall_name, "link") == 0) syscall_num = SYS_link;
#endif
#ifdef SYS_symlink
    else if (strcmp(syscall_name, "symlink") == 0) syscall_num = SYS_symlink;
#endif
#ifdef SYS_readlink
    else if (strcmp(syscall_name, "readlink") == 0) syscall_num = SYS_readlink;
#endif
#ifdef SYS_linkat
    else if (strcmp(syscall_name, "linkat") == 0) syscall_num = SYS_linkat;
#endif
#ifdef SYS_symlinkat
    else if (strcmp(syscall_name, "symlinkat") == 0) syscall_num = SYS_symlinkat;
#endif
#ifdef SYS_readlinkat
    else if (strcmp(syscall_name, "readlinkat") == 0) syscall_num = SYS_readlinkat;
#endif
#ifdef SYS_renameat2
    else if (strcmp(syscall_name, "renameat2") == 0) syscall_num = SYS_renameat2;
#endif
#ifdef SYS_statx
    else if (strcmp(syscall_name, "statx") == 0) syscall_num = SYS_statx;
#endif
#ifdef SYS_newfstatat
    else if (strcmp(syscall_name, "fstatat") == 0) syscall_num = SYS_newfstatat;
#endif
#ifdef SYS_faccessat
    else if (strcmp(syscall_name, "faccessat") == 0) syscall_num = SYS_faccessat;
#endif
#ifdef SYS_faccessat2
    else if (strcmp(syscall_name, "faccessat2") == 0) syscall_num = SYS_faccessat2;
#endif
#ifdef SYS_mknod
    else if (strcmp(syscall_name, "mknod") == 0) syscall_num = SYS_mknod;
#endif
#ifdef SYS_mknodat
    else if (strcmp(syscall_name, "mknodat") == 0) syscall_num = SYS_mknodat;
#endif
#ifdef SYS_chroot
    else if (strcmp(syscall_name, "chroot") == 0) syscall_num = SYS_chroot;
#endif
#ifdef SYS_pivot_root
    else if (strcmp(syscall_name, "pivot_root") == 0) syscall_num = SYS_pivot_root;
#endif
#ifdef SYS_umount2
    else if (strcmp(syscall_name, "umount2") == 0) syscall_num = SYS_umount2;
#endif

    // Memory & VM
#ifdef SYS_mremap
    else if (strcmp(syscall_name, "mremap") == 0) syscall_num = SYS_mremap;
#endif
#ifdef SYS_madvise
    else if (strcmp(syscall_name, "madvise") == 0) syscall_num = SYS_madvise;
#endif
#ifdef SYS_mincore
    else if (strcmp(syscall_name, "mincore") == 0) syscall_num = SYS_mincore;
#endif
#ifdef SYS_mlock
    else if (strcmp(syscall_name, "mlock") == 0) syscall_num = SYS_mlock;
#endif
#ifdef SYS_munlock
    else if (strcmp(syscall_name, "munlock") == 0) syscall_num = SYS_munlock;
#endif
#ifdef SYS_mlockall
    else if (strcmp(syscall_name, "mlockall") == 0) syscall_num = SYS_mlockall;
#endif
#ifdef SYS_munlockall
    else if (strcmp(syscall_name, "munlockall") == 0) syscall_num = SYS_munlockall;
#endif
#ifdef SYS_remap_file_pages
    else if (strcmp(syscall_name, "remap_file_pages") == 0) syscall_num = SYS_remap_file_pages;
#endif
#ifdef SYS_memfd_create
    else if (strcmp(syscall_name, "memfd_create") == 0) syscall_num = SYS_memfd_create;
#endif
#ifdef SYS_membarrier
    else if (strcmp(syscall_name, "membarrier") == 0) syscall_num = SYS_membarrier;
#endif

    // Time & scheduling
#ifdef SYS_nanosleep
    else if (strcmp(syscall_name, "nanosleep") == 0) syscall_num = SYS_nanosleep;
#endif
#ifdef SYS_clock_gettime
    else if (strcmp(syscall_name, "clock_gettime") == 0) syscall_num = SYS_clock_gettime;
#endif
#ifdef SYS_clock_settime
    else if (strcmp(syscall_name, "clock_settime") == 0) syscall_num = SYS_clock_settime;
#endif
#ifdef SYS_gettimeofday
    else if (strcmp(syscall_name, "gettimeofday") == 0) syscall_num = SYS_gettimeofday;
#endif
#ifdef SYS_times
    else if (strcmp(syscall_name, "times") == 0) syscall_num = SYS_times;
#endif
#ifdef SYS_sched_yield
    else if (strcmp(syscall_name, "sched_yield") == 0) syscall_num = SYS_sched_yield;
#endif
#ifdef SYS_sched_setaffinity
    else if (strcmp(syscall_name, "sched_setaffinity") == 0) syscall_num = SYS_sched_setaffinity;
#endif
#ifdef SYS_sched_getaffinity
    else if (strcmp(syscall_name, "sched_getaffinity") == 0) syscall_num = SYS_sched_getaffinity;
#endif
#ifdef SYS_sched_setscheduler
    else if (strcmp(syscall_name, "sched_setscheduler") == 0) syscall_num = SYS_sched_setscheduler;
#endif
#ifdef SYS_sched_getscheduler
    else if (strcmp(syscall_name, "sched_getscheduler") == 0) syscall_num = SYS_sched_getscheduler;
#endif
#ifdef SYS_sched_getparam
    else if (strcmp(syscall_name, "sched_getparam") == 0) syscall_num = SYS_sched_getparam;
#endif
#ifdef SYS_sched_setparam
    else if (strcmp(syscall_name, "sched_setparam") == 0) syscall_num = SYS_sched_setparam;
#endif

    // Signals
#ifdef SYS_rt_sigaction
    else if (strcmp(syscall_name, "rt_sigaction") == 0) syscall_num = SYS_rt_sigaction;
#endif
#ifdef SYS_rt_sigprocmask
    else if (strcmp(syscall_name, "rt_sigprocmask") == 0) syscall_num = SYS_rt_sigprocmask;
#endif
#ifdef SYS_rt_sigsuspend
    else if (strcmp(syscall_name, "rt_sigsuspend") == 0) syscall_num = SYS_rt_sigsuspend;
#endif
#ifdef SYS_rt_sigqueueinfo
    else if (strcmp(syscall_name, "rt_sigqueueinfo") == 0) syscall_num = SYS_rt_sigqueueinfo;
#endif
#ifdef SYS_signalfd4
    else if (strcmp(syscall_name, "signalfd4") == 0) syscall_num = SYS_signalfd4;
#endif
#ifdef SYS_tkill
    else if (strcmp(syscall_name, "tkill") == 0) syscall_num = SYS_tkill;
#endif

    // Process & namespaces
#ifdef SYS_prctl
    else if (strcmp(syscall_name, "prctl") == 0) syscall_num = SYS_prctl;
#endif
#ifdef SYS_setns
    else if (strcmp(syscall_name, "setns") == 0) syscall_num = SYS_setns;
#endif
#ifdef SYS_unshare
    /* already mapped above (kept here just to show we considered it) */
#endif
#ifdef SYS_kcmp
    else if (strcmp(syscall_name, "kcmp") == 0) syscall_num = SYS_kcmp;
#endif
#ifdef SYS_pidfd_open
    else if (strcmp(syscall_name, "pidfd_open") == 0) syscall_num = SYS_pidfd_open;
#endif
#ifdef SYS_pidfd_send_signal
    else if (strcmp(syscall_name, "pidfd_send_signal") == 0) syscall_num = SYS_pidfd_send_signal;
#endif
#ifdef SYS_pidfd_getfd
    else if (strcmp(syscall_name, "pidfd_getfd") == 0) syscall_num = SYS_pidfd_getfd;
#endif
#ifdef SYS_clone3
    else if (strcmp(syscall_name, "clone3") == 0) syscall_num = SYS_clone3;
#endif
#ifdef SYS_execveat
    else if (strcmp(syscall_name, "execveat") == 0) syscall_num = SYS_execveat;
#endif
#ifdef SYS_prlimit64
    else if (strcmp(syscall_name, "prlimit64") == 0) syscall_num = SYS_prlimit64;
#endif
#ifdef SYS_getpriority
    else if (strcmp(syscall_name, "getpriority") == 0) syscall_num = SYS_getpriority;
#endif
#ifdef SYS_setpriority
    else if (strcmp(syscall_name, "setpriority") == 0) syscall_num = SYS_setpriority;
#endif
#ifdef SYS_nice
    else if (strcmp(syscall_name, "nice") == 0) syscall_num = SYS_nice;
#endif

    // Futex & threads
#ifdef SYS_futex
    else if (strcmp(syscall_name, "futex") == 0) syscall_num = SYS_futex;
#endif
#ifdef SYS_set_robust_list
    else if (strcmp(syscall_name, "set_robust_list") == 0) syscall_num = SYS_set_robust_list;
#endif
#ifdef SYS_get_robust_list
    else if (strcmp(syscall_name, "get_robust_list") == 0) syscall_num = SYS_get_robust_list;
#endif
#ifdef SYS_set_tid_address
    else if (strcmp(syscall_name, "set_tid_address") == 0) syscall_num = SYS_set_tid_address;
#endif

    // Randomness & crypto-ish
#ifdef SYS_getrandom
    else if (strcmp(syscall_name, "getrandom") == 0) syscall_num = SYS_getrandom;
#endif
#ifdef SYS_keyctl
    /* already mapped above */
#endif

    // Timers, eventfds, perf
#ifdef SYS_timer_create
    else if (strcmp(syscall_name, "timer_create") == 0) syscall_num = SYS_timer_create;
#endif
#ifdef SYS_timer_settime
    else if (strcmp(syscall_name, "timer_settime") == 0) syscall_num = SYS_timer_settime;
#endif
#ifdef SYS_timer_gettime
    else if (strcmp(syscall_name, "timer_gettime") == 0) syscall_num = SYS_timer_gettime;
#endif
#ifdef SYS_timer_getoverrun
    else if (strcmp(syscall_name, "timer_getoverrun") == 0) syscall_num = SYS_timer_getoverrun;
#endif
#ifdef SYS_timer_delete
    else if (strcmp(syscall_name, "timer_delete") == 0) syscall_num = SYS_timer_delete;
#endif
#ifdef SYS_eventfd2
    else if (strcmp(syscall_name, "eventfd2") == 0) syscall_num = SYS_eventfd2;
#endif
#ifdef SYS_timerfd_create
    else if (strcmp(syscall_name, "timerfd_create") == 0) syscall_num = SYS_timerfd_create;
#endif
#ifdef SYS_timerfd_settime
    else if (strcmp(syscall_name, "timerfd_settime") == 0) syscall_num = SYS_timerfd_settime;
#endif
#ifdef SYS_timerfd_gettime
    else if (strcmp(syscall_name, "timerfd_gettime") == 0) syscall_num = SYS_timerfd_gettime;
#endif
#ifdef SYS_perf_event_open
    else if (strcmp(syscall_name, "perf_event_open") == 0) syscall_num = SYS_perf_event_open;
#endif
#ifdef SYS_eventfd
    else if (strcmp(syscall_name, "eventfd") == 0) syscall_num = SYS_eventfd;
#endif
#ifdef SYS_signalfd
    else if (strcmp(syscall_name, "signalfd") == 0) syscall_num = SYS_signalfd;
#endif

    // Inotify / fanotify
#ifdef SYS_inotify_init1
    else if (strcmp(syscall_name, "inotify_init1") == 0) syscall_num = SYS_inotify_init1;
#endif
#ifdef SYS_inotify_add_watch
    else if (strcmp(syscall_name, "inotify_add_watch") == 0) syscall_num = SYS_inotify_add_watch;
#endif
#ifdef SYS_inotify_rm_watch
    else if (strcmp(syscall_name, "inotify_rm_watch") == 0) syscall_num = SYS_inotify_rm_watch;
#endif
#ifdef SYS_fanotify_init
    else if (strcmp(syscall_name, "fanotify_init") == 0) syscall_num = SYS_fanotify_init;
#endif
#ifdef SYS_fanotify_mark
    else if (strcmp(syscall_name, "fanotify_mark") == 0) syscall_num = SYS_fanotify_mark;
#endif

    // XAttrs
#ifdef SYS_setxattr
    else if (strcmp(syscall_name, "setxattr") == 0) syscall_num = SYS_setxattr;
#endif
#ifdef SYS_lsetxattr
    else if (strcmp(syscall_name, "lsetxattr") == 0) syscall_num = SYS_lsetxattr;
#endif
#ifdef SYS_fsetxattr
    else if (strcmp(syscall_name, "fsetxattr") == 0) syscall_num = SYS_fsetxattr;
#endif
#ifdef SYS_getxattr
    else if (strcmp(syscall_name, "getxattr") == 0) syscall_num = SYS_getxattr;
#endif
#ifdef SYS_lgetxattr
    else if (strcmp(syscall_name, "lgetxattr") == 0) syscall_num = SYS_lgetxattr;
#endif
#ifdef SYS_fgetxattr
    else if (strcmp(syscall_name, "fgetxattr") == 0) syscall_num = SYS_fgetxattr;
#endif
#ifdef SYS_listxattr
    else if (strcmp(syscall_name, "listxattr") == 0) syscall_num = SYS_listxattr;
#endif
#ifdef SYS_llistxattr
    else if (strcmp(syscall_name, "llistxattr") == 0) syscall_num = SYS_llistxattr;
#endif
#ifdef SYS_flistxattr
    else if (strcmp(syscall_name, "flistxattr") == 0) syscall_num = SYS_flistxattr;
#endif
#ifdef SYS_removexattr
    else if (strcmp(syscall_name, "removexattr") == 0) syscall_num = SYS_removexattr;
#endif
#ifdef SYS_lremovexattr
    else if (strcmp(syscall_name, "lremovexattr") == 0) syscall_num = SYS_lremovexattr;
#endif
#ifdef SYS_fremovexattr
    else if (strcmp(syscall_name, "fremovexattr") == 0) syscall_num = SYS_fremovexattr;
#endif

    // SysV IPC
#ifdef SYS_shmget
    else if (strcmp(syscall_name, "shmget") == 0) syscall_num = SYS_shmget;
#endif
#ifdef SYS_shmat
    else if (strcmp(syscall_name, "shmat") == 0) syscall_num = SYS_shmat;
#endif
#ifdef SYS_shmdt
    else if (strcmp(syscall_name, "shmdt") == 0) syscall_num = SYS_shmdt;
#endif
#ifdef SYS_shmctl
    else if (strcmp(syscall_name, "shmctl") == 0) syscall_num = SYS_shmctl;
#endif
#ifdef SYS_semget
    else if (strcmp(syscall_name, "semget") == 0) syscall_num = SYS_semget;
#endif
#ifdef SYS_semop
    else if (strcmp(syscall_name, "semop") == 0) syscall_num = SYS_semop;
#endif
#ifdef SYS_semctl
    else if (strcmp(syscall_name, "semctl") == 0) syscall_num = SYS_semctl;
#endif
#ifdef SYS_msgget
    else if (strcmp(syscall_name, "msgget") == 0) syscall_num = SYS_msgget;
#endif
#ifdef SYS_msgsnd
    else if (strcmp(syscall_name, "msgsnd") == 0) syscall_num = SYS_msgsnd;
#endif
#ifdef SYS_msgrcv
    else if (strcmp(syscall_name, "msgrcv") == 0) syscall_num = SYS_msgrcv;
#endif
#ifdef SYS_msgctl
    else if (strcmp(syscall_name, "msgctl") == 0) syscall_num = SYS_msgctl;
#endif

    // Networking extras
#ifdef SYS_accept4
    else if (strcmp(syscall_name, "accept4") == 0) syscall_num = SYS_accept4;
#endif
#ifdef SYS_recvmmsg
    else if (strcmp(syscall_name, "recvmmsg") == 0) syscall_num = SYS_recvmmsg;
#endif
#ifdef SYS_sendmmsg
    else if (strcmp(syscall_name, "sendmmsg") == 0) syscall_num = SYS_sendmmsg;
#endif
#ifdef SYS_sendmsg
    else if (strcmp(syscall_name, "sendmsg") == 0) syscall_num = SYS_sendmsg;
#endif
#ifdef SYS_recvmsg
    else if (strcmp(syscall_name, "recvmsg") == 0) syscall_num = SYS_recvmsg;
#endif

    // Filesystem notifications & quotas
#ifdef SYS_quotactl
    else if (strcmp(syscall_name, "quotactl") == 0) syscall_num = SYS_quotactl;
#endif

    // Control / admin (use inside VM/sandbox)
#ifdef SYS_reboot
    else if (strcmp(syscall_name, "reboot") == 0) syscall_num = SYS_reboot;
#endif
#ifdef SYS_kexec_load
    else if (strcmp(syscall_name, "kexec_load") == 0) syscall_num = SYS_kexec_load;
#endif

    // io_uring family
#ifdef SYS_io_uring_enter
    else if (strcmp(syscall_name, "io_uring_enter") == 0) syscall_num = SYS_io_uring_enter;
#endif
#ifdef SYS_io_uring_register
    else if (strcmp(syscall_name, "io_uring_register") == 0) syscall_num = SYS_io_uring_register;
#endif

    // Landlock / security (if present)
#ifdef SYS_landlock_add_rule
    else if (strcmp(syscall_name, "landlock_add_rule") == 0) syscall_num = SYS_landlock_add_rule;
#endif
#ifdef SYS_landlock_create_ruleset
    else if (strcmp(syscall_name, "landlock_create_ruleset") == 0) syscall_num = SYS_landlock_create_ruleset;
#endif
#ifdef SYS_landlock_restrict_self
    else if (strcmp(syscall_name, "landlock_restrict_self") == 0) syscall_num = SYS_landlock_restrict_self;
#endif

    // Misc quality-of-life
#ifdef SYS_pipe2
    else if (strcmp(syscall_name, "pipe2") == 0) syscall_num = SYS_pipe2;
#endif
#ifdef SYS_dup3
    else if (strcmp(syscall_name, "dup3") == 0) syscall_num = SYS_dup3;
#endif
#ifdef SYS_getcpu
    else if (strcmp(syscall_name, "getcpu") == 0) syscall_num = SYS_getcpu;
#endif
#ifdef SYS_getrandom
    /* already mapped above */
#endif

    if (syscall_num == -1) {
        fprintf(stderr, "Error: Unknown syscall '%s'\n", syscall_name);
        return 1;
    }

    // --- Argument Parsing and Execution ---
    long args[6] = {0};
    int num_args = argc - 2;
    if (num_args > 6) num_args = 6;

    for (int i = 0; i < num_args; i++) {
        args[i] = get_arg(argv[i + 2]);
    }

    // Print call details for logging
    printf("Fuzzing attempt: %s(", syscall_name);
    for (int i = 0; i < num_args; i++) {
        printf("0x%lx%s", args[i], (i == num_args - 1) ? "" : ", ");
    }
    printf(")\n");
    fflush(stdout);

    // Perform the syscall
    long ret = syscall(syscall_num, args[0], args[1], args[2], args[3], args[4], args[5]);

    // Print return value
    printf("syscall(%ld) = %ld\n", syscall_num, ret);
    return 0;
}
