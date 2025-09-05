#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

// This program is the "worker" that runs inside the VM.
// Its job is to take a syscall name and arguments from the command line,
// translate the name into a number the kernel understands, and execute it.

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <syscall_name> [args...]\n", argv[0]);
        return 1;
    }

    const char *syscall_name = argv[1];
    long syscall_num = -1;

    // --- Syscall Name to Number Translation ---
    // This must be kept in sync with the syscalls defined in fuzzer_config.py
    // to ensure all generated tests can be executed.

    if (strcmp(syscall_name, "read") == 0) syscall_num = SYS_read;
    else if (strcmp(syscall_name, "write") == 0) syscall_num = SYS_write;
    else if (strcmp(syscall_name, "open") == 0) syscall_num = SYS_open;
    else if (strcmp(syscall_name, "close") == 0) syscall_num = SYS_close;
    else if (strcmp(syscall_name, "mmap") == 0) syscall_num = SYS_mmap;
    else if (strcmp(syscall_name, "ptrace") == 0) syscall_num = SYS_ptrace;
    else if (strcmp(syscall_name, "mount") == 0) syscall_num = SYS_mount;
    else if (strcmp(syscall_name, "unshare") == 0) syscall_num = SYS_unshare;
    else if (strcmp(syscall_name, "seccomp") == 0) syscall_num = SYS_seccomp;
    else if (strcmp(syscall_name, "userfaultfd") == 0) syscall_num = SYS_userfaultfd;
    else if (strcmp(syscall_name, "ioctl") == 0) syscall_num = SYS_ioctl;
    else if (strcmp(syscall_name, "bpf") == 0) syscall_num = SYS_bpf;
    else if (strcmp(syscall_name, "io_uring_setup") == 0) syscall_num = SYS_io_uring_setup;
    else if (strcmp(syscall_name, "keyctl") == 0) syscall_num = SYS_keyctl;
    else if (strcmp(syscall_name, "socket") == 0) syscall_num = SYS_socket;
    else if (strcmp(syscall_name, "setsockopt") == 0) syscall_num = SYS_setsockopt;
    // Also include some common ones that might not be in the current config
    else if (strcmp(syscall_name, "mprotect") == 0) syscall_num = SYS_mprotect;
    else if (strcmp(syscall_name, "munmap") == 0) syscall_num = SYS_munmap;
    else {
        fprintf(stderr, "Error: Unknown syscall '%s'\n", syscall_name);
        return 1;
    }

    // --- Argument Parsing and Execution ---
    long args[6] = {0};
    int num_args = argc - 2;
    if (num_args > 6) num_args = 6;

    printf("Fuzzing attempt: %s(", syscall_name);
    for (int i = 0; i < num_args; i++) {
        // Use strtol to correctly parse hex/decimal numbers from the fuzzer
        args[i] = strtol(argv[i + 2], NULL, 0);
        printf("0x%lx%s", args[i], (i == num_args - 1) ? "" : ", ");
    }
    printf(")\n");
    fflush(stdout); // Ensure the line is printed before the syscall is made

    // The actual syscall is made here. The kernel does the rest.
    syscall(syscall_num, args[0], args[1], args[2], args[3], args[4], args[5]);

    // If the program reaches here, the syscall returned and did not crash the kernel.
    return 0;
}

