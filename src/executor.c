#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

// A simple helper to convert string arguments to long integers
long get_arg(char *arg) {
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
    // This is a comprehensive list combining all previous research and contributions.
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

    // We print the call details so the fuzzer brain can log it.
    printf("Fuzzing attempt: %s(", syscall_name);
    for (int i = 0; i < num_args; i++) {
        printf("0x%lx%s", args[i], (i == num_args - 1) ? "" : ", ");
    }
    printf(")\n");
    fflush(stdout);

    // The actual system call is made here.
    long ret = syscall(syscall_num, args[0], args[1], args[2], args[3], args[4], args[5]);
    
    // We print the return value so the stateful fuzzer can potentially use it.
    printf("syscall(%ld) = %ld\n", syscall_num, ret);

    return 0;
}
