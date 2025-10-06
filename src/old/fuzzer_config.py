import random
import os
import time

# -----------------------
# Interesting Values
# -----------------------

INTERESTING_VALUES = {
    "int": [-1, 0, 1, 2, 64, 1024, 4096, 0x7FFFFFFF, 0xFFFFFFFF],
    "flags": [0, 1, 2, 0x80000000, 0xFFFFFFFF],
    "pid": [-1, 0, 1, 2],
    "mode": [0o777, 0o644, 0o600, 0o755, 0],
}

# -----------------------
# Type Generators
# -----------------------

def gen_random_int(arg_spec=None):
    return random.randint(-2**31, 2**31 - 1)

def gen_fd(arg_spec=None):
    return random.choice(INTERESTING_VALUES["int"] + [-1, 0, 1, 2])

def gen_addr(arg_spec=None):
    return random.choice([0, 0x1000, 0x80000000, 0xC0000000, gen_random_int()])

def gen_size(arg_spec=None):
    return random.choice(INTERESTING_VALUES["int"] + [16, 128, 512, 4096])

def gen_pid(arg_spec=None):
    return random.choice(INTERESTING_VALUES["pid"])

def gen_mode(arg_spec=None):
    return random.choice(INTERESTING_VALUES["mode"])

def gen_mmap_flags_cve(arg_spec=None):
    base_flags = [0x1, 0x2, 0x10]  # MAP_SHARED, MAP_PRIVATE, MAP_ANONYMOUS
    return random.choice(base_flags) | random.choice(INTERESTING_VALUES["flags"])

def gen_ptrace_req_cve(arg_spec=None):
    return 0  # PTRACE_TRACEME

def gen_userfaultfd_flags(arg_spec=None):
    return random.choice([0, 1, 4])  # O_CLOEXEC, O_NONBLOCK

def gen_seccomp_flags(arg_spec=None):
    return random.choice([0, 1, 2])  # SECCOMP_MODE_STRICT, SECCOMP_MODE_FILTER

def gen_ioctl_request(arg_spec=None):
    return random.choice([0x5401, 0x5413, gen_random_int()])

def gen_bpf_cmd(arg_spec=None):
    return random.randint(0, 15)

def gen_keyctl_cmd(arg_spec=None):
    return random.randint(0, 20)

def gen_socket_domain(arg_spec=None):
    return random.choice([2, 10, 1, 16])  # AF_INET, AF_INET6, AF_UNIX, AF_NETLINK

def gen_socket_type(arg_spec=None):
    return random.choice([1, 2, 3])  # SOCK_STREAM, SOCK_DGRAM, SOCK_RAW

# Map type strings to generator functions
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

# -----------------------
# Syscall Specifications
# -----------------------
SYSCALL_SPECS = {
    # Memory Management
    "mmap": ["addr", "size", "flags", "fd", "size"],
    "mremap": ["addr", "size", "size", "flags", "addr"],
    "msync": ["addr", "size", "flags"],
    "mlock": ["addr", "size"],
    "munlock": ["addr", "size"],

    # Files / FS
    "open": ["addr", "flags", "mode"],
    "openat": ["fd", "addr", "flags", "mode"],
    "close": ["fd"],
    "read": ["fd", "addr", "size"],
    "write": ["fd", "addr", "size"],
    "lseek": ["fd", "random_int", "random_int"],
    "pread64": ["fd", "addr", "size", "random_int"],
    "pwrite64": ["fd", "addr", "size", "random_int"],
    "stat": ["addr", "addr"],
    "fstat": ["fd", "addr"],
    "lstat": ["addr", "addr"],
    "unlink": ["addr"],
    "unlinkat": ["fd", "addr", "flags"],
    "rename": ["addr", "addr"],
    "renameat": ["fd", "addr", "fd", "addr"],
    "symlink": ["addr", "addr"],
    "readlink": ["addr", "addr", "size"],
    "truncate": ["addr", "size"],
    "ftruncate": ["fd", "size"],
    "access": ["addr", "flags"],
    "chmod": ["addr", "mode"],
    "chown": ["addr", "random_int", "random_int"],

    # Process / Signals
    "fork": [],
    "vfork": [],
    "clone": ["flags", "addr", "addr", "addr", "addr"],
    "clone3": ["addr", "size"],
    "execve": ["addr", "addr", "addr"],
    "exit": ["random_int"],
    "wait4": ["pid", "addr", "flags", "addr"],
    "kill": ["pid", "random_int"],
    "tgkill": ["pid", "pid", "random_int"],
    "getpid": [],
    "getppid": [],
    "getuid": [],
    "geteuid": [],
    "getgid": [],
    "getegid": [],
    "setsid": [],
    "setuid": ["pid"],
    "setgid": ["pid"],

    # Networking
    "socket": ["socket_domain", "socket_type", "flags"],
    "socketpair": ["socket_domain", "socket_type", "flags", "addr"],
    "connect": ["fd", "addr", "size"],
    "accept": ["fd", "addr", "addr"],
    "bind": ["fd", "addr", "size"],
    "listen": ["fd", "random_int"],
    "sendto": ["fd", "addr", "size", "flags", "addr", "size"],
    "recvfrom": ["fd", "addr", "size", "flags", "addr", "addr"],
    "sendmsg": ["fd", "addr", "size"],
    "recvmsg": ["fd", "addr", "size"],
    "getsockname": ["fd", "addr", "addr"],
    "getpeername": ["fd", "addr", "addr"],
    "setsockopt": ["fd", "random_int", "random_int", "addr", "size"],
    "getsockopt": ["fd", "random_int", "random_int", "addr", "addr"],

    # Advanced / CVE / Kernel
    "ioctl": ["fd", "ioctl_request", "addr"],
    "bpf": ["bpf_cmd", "addr", "size"],
    "keyctl": ["keyctl_cmd", "flags", "size", "addr"],
    "userfaultfd": ["userfaultfd_flags"],
    "seccomp": ["seccomp_flags", "flags", "addr"],
    "ptrace": ["ptrace_req_cve", "pid", "addr", "addr"],
    "mount": ["addr", "addr", "addr", "flags", "addr"],
    "unshare": ["flags"],
    "init_module": ["addr", "size", "addr"],
    "finit_module": ["fd", "addr", "flags"],
    "io_uring_setup": ["size", "addr"],
    "capset": ["addr", "addr"],
    "reboot": ["random_int", "random_int", "addr", "size"],
    "perf_event_open": ["addr", "pid", "cpu", "fd", "flags"],
    "setns": ["fd", "flags"],
}

# -----------------------
# Syscall Sequences
# -----------------------
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
