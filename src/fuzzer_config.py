import random
import os
import time

# A collection of "interesting" values to be used by generators.
INTERESTING_VALUES = {
    "int": [-1, 0, 1, 2, 64, 1024, 4096, 0x7FFFFFFF, 0xFFFFFFFF],
    "flags": [0, 1, 2, 0x80000000, 0xFFFFFFFF],
    "pid": [-1, 0, 1, 2],
    "mode": [0o777, 0o644, 0o600, 0o755, 0],
}

# --- Argument Type Generators ---
# These functions generate values for specific argument types.

def gen_random_int(arg_spec=None):
    """Generates a completely random 32-bit integer."""
    return random.randint(-2**31, 2**31 - 1)

def gen_fd(arg_spec=None):
    """Generates a file descriptor, prioritizing interesting values."""
    return random.choice(INTERESTING_VALUES["int"] + [-1, 0, 1, 2])

def gen_addr(arg_spec=None):
    """Generates a memory address, prioritizing NULL and page boundaries."""
    return random.choice([0, 0x1000, 0x80000000, 0xC0000000, gen_random_int()])

def gen_size(arg_spec=None):
    """Generates a size value."""
    return random.choice(INTERESTING_VALUES["int"] + [16, 128, 512, 4096])

def gen_pid(arg_spec=None):
    """Generates a process ID."""
    return random.choice(INTERESTING_VALUES["pid"])

def gen_mode(arg_spec=None):
    """Generates a file permission mode."""
    return random.choice(INTERESTING_VALUES["mode"])

# --- CVE & Subsystem Specific Generators ---

def gen_mmap_flags_cve(arg_spec=None):
    """Generates flags relevant to mmap."""
    base_flags = [0x1, 0x2, 0x10] # MAP_SHARED, MAP_PRIVATE, MAP_ANONYMOUS
    return random.choice(base_flags) | random.choice(INTERESTING_VALUES["flags"])

def gen_ptrace_req_cve(arg_spec=None):
    """Generates ptrace requests, including PTRACE_TRACEME."""
    return 0 # PTRACE_TRACEME

def gen_userfaultfd_flags(arg_spec=None):
    """Generates flags for userfaultfd."""
    return random.choice([0, 1, 4]) # O_CLOEXEC, O_NONBLOCK

def gen_seccomp_flags(arg_spec=None):
    """Generates flags for seccomp."""
    return random.choice([0, 1, 2]) # SECCOMP_MODE_STRICT, SECCOMP_MODE_FILTER

def gen_ioctl_request(arg_spec=None):
    """Generates a pseudo-random ioctl request code."""
    return random.choice([0x5401, 0x5413, gen_random_int()])

def gen_bpf_cmd(arg_spec=None):
    """Generates a command for the bpf syscall."""
    return random.randint(0, 15)

def gen_keyctl_cmd(arg_spec=None):
    """Generates a command for keyctl."""
    return random.randint(0, 20)

def gen_socket_domain(arg_spec=None):
    """Generates a socket domain."""
    return random.choice([2, 10, 1, 16]) # AF_INET, AF_INET6, AF_UNIX, AF_NETLINK

def gen_socket_type(arg_spec=None):
    """Generates a socket type."""
    return random.choice([1, 2, 3]) # SOCK_STREAM, SOCK_DGRAM, SOCK_RAW

# Mapping of type names to generator functions
TYPE_GENERATORS = {
    "random_int": gen_random_int,
    "fd": gen_fd,
    "addr": gen_addr,
    "size": gen_size,
    "flags": lambda spec: random.choice(INTERESTING_VALUES["flags"]),
    "pid": gen_pid,
    "mode": gen_mode,
    "mmap_flags_cve": gen_mmap_flags_cve,
    "ptrace_req_cve": gen_ptrace_req_cve,
    "userfaultfd_flags": gen_userfaultfd_flags,
    "seccomp_flags": gen_seccomp_flags,
    "ioctl_request": gen_ioctl_request,
    "bpf_cmd": gen_bpf_cmd,
    "keyctl_cmd": gen_keyctl_cmd,
    "socket_domain": gen_socket_domain,
    "socket_type": gen_socket_type,
}

# --- Syscall Definitions ---
# This dictionary defines the syscalls we want to fuzz and their arguments.
SYSCALL_SPECS = {
    # Tier 1: High-Impact Memory Corruption
    "setsockopt": ["fd", "random_int", "random_int", "addr", "size"],
    "getsockopt": ["fd", "random_int", "random_int", "addr", "addr"],
    "ioctl": ["fd", "ioctl_request", "addr"],
    "bpf": ["bpf_cmd", "addr", "size"],
    "socket": ["socket_domain", "socket_type", "flags"],
    "connect": ["fd", "addr", "size"],
    "accept": ["fd", "addr", "addr"],
    "bind": ["fd", "addr", "size"],
    "listen": ["fd", "random_int"],
    "sendto": ["fd", "addr", "size", "flags", "addr", "size"],
    "recvfrom": ["fd", "addr", "size", "flags", "addr", "addr"],

    # Tier 2: Privilege Escalation & Concurrency
    "mount": ["addr", "addr", "addr", "flags", "addr"],
    "chown": ["addr", "random_int", "random_int"],
    "chmod": ["addr", "mode"],
    "init_module": ["addr", "size", "addr"],
    "finit_module": ["fd", "addr", "flags"],
    "unshare": ["flags"],

    # Tier 3: Environment-Specific & Advanced Targets
    "openat": ["fd", "addr", "flags", "mode"],
    "unlinkat": ["fd", "addr", "flags"],
    "renameat": ["fd", "addr", "fd", "addr"],
    "setuid": ["pid"],
    "setgid": ["pid"],
    "capset": ["addr", "addr"],
    "mmap": ["addr", "size", "flags", "fd", "size"],
    "ptrace": ["ptrace_req_cve", "pid", "addr", "addr"],

    # General Purpose & High Frequency
    "read": ["fd", "addr", "size"],
    "write": ["fd", "addr", "size"],
    "open": ["addr", "flags", "mode"],
    "close": ["fd"],
    "lseek": ["fd", "random_int", "random_int"],
    "pread64": ["fd", "addr", "size", "random_int"],
    "pwrite64": ["fd", "addr", "size", "random_int"],
    "dup": ["fd"],
    "dup2": ["fd", "fd"],
    "stat": ["addr", "addr"],
    "fstat": ["fd", "addr"],
    "unlink": ["addr"],
    "rename": ["addr", "addr"],
    "fork": [],
    "vfork": [],
    "clone": ["flags", "addr", "addr", "addr", "addr"],
    "execve": ["addr", "addr", "addr"],
    "exit": ["random_int"],
    "wait4": ["pid", "addr", "flags", "addr"],
    "kill": ["pid", "random_int"],
    "tgkill": ["pid", "pid", "random_int"],
    "userfaultfd": ["userfaultfd_flags"],
    "seccomp": ["seccomp_flags", "flags", "addr"],
    "io_uring_setup": ["size", "addr"],
    "keyctl": ["keyctl_cmd", "flags", "size", "addr"],
}

# --- Syscall Sequences ---
# Sequences allow multi-step tests with dependency between calls.
# If a step has "result": "fd1", the executor return value is stored as env["fd1"].
# Later steps can use {"value": "fd1"} to substitute it into args.
SYSCALL_SEQUENCES = {
    "uaf_double_close": [
        {"action": "open", "args": ["addr", "flags", "mode"], "result": "fd1"},
        {"action": "close", "args": [{"value": "fd1"}]},
        {"action": "close", "args": [{"value": "fd1"}]}
    ],
    "uaf_use_after_close": [
        {"action": "open", "args": ["addr", "flags", "mode"], "result": "fd1"},
        {"action": "close", "args": [{"value": "fd1"}]},
        {"action": "write", "args": [{"value": "fd1"}, "addr", "size"]}
    ],
    "move_mount_panic": [
        {"action": "unshare", "args": ["flags"]},
        {"action": "mount", "args": ["addr", "addr", "addr", "flags", "addr"]},
    ],
    "seccomp_ptrace_bypass_test": [
       {"action": "seccomp", "args": ["seccomp_flags", "flags", "addr"]},
       {"action": "ptrace", "args": ["ptrace_req_cve", "pid", "addr", "addr"]},
    ]
}
