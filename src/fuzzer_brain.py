import random
import os
import time

# -----------------------
# Interesting Values
# -----------------------

INTERESTING_VALUES = {
    "int": [-1, 0, 1, 2, 64, 1024, 4096, 8192, 0x7FFFFFFF, 0xFFFFFFFF, -2147483648],
    "flags": [0, 1, 2, 4, 8, 0x80000000, 0xFFFFFFFF, 0x7FFFFFFF],
    "pid": [-1, 0, 1, 2, 32768, 65535],
    "mode": [0o777, 0o644, 0o600, 0o755, 0o400, 0o000, 0o4755],
    "offset": [0, 1, -1, 4096, 0x7FFFFFFF, -0x80000000],
}

# -----------------------
# Type Generators
# -----------------------

def gen_random_int(arg_spec=None):
    """Generate random integer with bias towards interesting values"""
    if random.random() < 0.3:
        return random.choice(INTERESTING_VALUES["int"])
    return random.randint(-2**31, 2**31 - 1)

def gen_fd(arg_spec=None):
    """Generate file descriptor"""
    return random.choice(INTERESTING_VALUES["int"] + [-1, 0, 1, 2, 3, 100, 1000])

def gen_addr(arg_spec=None):
    """Generate memory address with interesting values"""
    interesting = [0, 0x1000, 0x10000, 0x7FFFFFFF, 0x80000000, 0xC0000000, 0xFFFFFFFF]
    if random.random() < 0.4:
        return random.choice(interesting)
    return random.randint(0, 0xFFFFFFFF)

def gen_size(arg_spec=None):
    """Generate size with various ranges"""
    sizes = [0, 1, 16, 64, 128, 256, 512, 1024, 4096, 8192, 65536, 0x7FFFFFFF, 0xFFFFFFFF]
    return random.choice(sizes)

def gen_pid(arg_spec=None):
    """Generate process ID"""
    return random.choice(INTERESTING_VALUES["pid"])

def gen_mode(arg_spec=None):
    """Generate file mode/permissions"""
    return random.choice(INTERESTING_VALUES["mode"])

def gen_offset(arg_spec=None):
    """Generate file offset"""
    return random.choice(INTERESTING_VALUES["offset"])

def gen_flags(arg_spec=None):
    """Generate generic flags"""
    return random.choice(INTERESTING_VALUES["flags"])

def gen_signal(arg_spec=None):
    """Generate signal number"""
    return random.choice([0, 1, 2, 9, 11, 15, 17, 19, 31, 64])

def gen_cpu(arg_spec=None):
    """Generate CPU number"""
    return random.choice([-1, 0, 1, 2, 4, 8, 64])

# File-related generators
def gen_open_flags(arg_spec=None):
    """Generate open() flags"""
    base = random.choice([0, 1, 2])  # O_RDONLY, O_WRONLY, O_RDWR
    extra = random.choice([0, 0x40, 0x200, 0x400, 0x800, 0x1000])  # O_CREAT, O_TRUNC, etc
    return base | extra

def gen_mmap_prot(arg_spec=None):
    """Generate mmap protection flags"""
    return random.choice([0, 1, 2, 3, 4, 5, 6, 7])  # PROT_NONE to PROT_READ|WRITE|EXEC

def gen_mmap_flags(arg_spec=None):
    """Generate mmap flags"""
    base = random.choice([0x1, 0x2])  # MAP_SHARED, MAP_PRIVATE
    extra = random.choice([0, 0x10, 0x20, 0x100, 0x1000, 0x8000])
    return base | extra

def gen_mmap_flags_cve(arg_spec=None):
    """Generate mmap flags for CVE testing"""
    base_flags = [0x1, 0x2, 0x10]  # MAP_SHARED, MAP_PRIVATE, MAP_ANONYMOUS
    return random.choice(base_flags) | random.choice(INTERESTING_VALUES["flags"])

# Network-related generators
def gen_socket_domain(arg_spec=None):
    """Generate socket domain/family"""
    return random.choice([1, 2, 10, 16, 17, 29, 40])  # AF_UNIX, AF_INET, AF_INET6, etc

def gen_socket_type(arg_spec=None):
    """Generate socket type"""
    base = random.choice([1, 2, 3, 5])  # SOCK_STREAM, SOCK_DGRAM, SOCK_RAW, SOCK_SEQPACKET
    flags = random.choice([0, 0x80000, 0x800])  # SOCK_NONBLOCK, SOCK_CLOEXEC
    return base | flags

def gen_socket_protocol(arg_spec=None):
    """Generate socket protocol"""
    return random.choice([0, 1, 6, 17, 132, 255])

def gen_sockopt_level(arg_spec=None):
    """Generate socket option level"""
    return random.choice([1, 6, 17, 41, 132, 263])  # SOL_SOCKET, IPPROTO_TCP, etc

# Process-related generators
def gen_clone_flags(arg_spec=None):
    """Generate clone() flags"""
    flags = [0x00010000, 0x00020000, 0x00040000, 0x00080000, 0x00200000, 0x01000000]
    result = 0
    for _ in range(random.randint(0, 3)):
        result |= random.choice(flags)
    return result

def gen_wait_options(arg_spec=None):
    """Generate wait4() options"""
    return random.choice([0, 1, 2, 4, 8])  # WNOHANG, WUNTRACED, etc

# I/O and event-related generators
def gen_epoll_events(arg_spec=None):
    """Generate epoll events"""
    events = [0x001, 0x004, 0x008, 0x010, 0x020]
    result = 0
    for _ in range(random.randint(1, 3)):
        result |= random.choice(events)
    return result

def gen_poll_events(arg_spec=None):
    """Generate poll events"""
    return random.choice([0x001, 0x002, 0x004, 0x008, 0x010, 0x020])

def gen_fcntl_cmd(arg_spec=None):
    """Generate fcntl command"""
    return random.choice([0, 1, 2, 3, 4, 5, 6, 7, 8, 1024, 1025, 1026])

# Advanced/CVE generators
def gen_ptrace_req_cve(arg_spec=None):
    """Generate ptrace request"""
    return random.choice([0, 1, 2, 3, 4, 5, 6, 12, 16, 0x4200, 0x4201])

def gen_userfaultfd_flags(arg_spec=None):
    """Generate userfaultfd flags"""
    return random.choice([0, 1, 4, 0x80000])  # O_CLOEXEC, O_NONBLOCK, etc

def gen_seccomp_flags(arg_spec=None):
    """Generate seccomp flags"""
    return random.choice([0, 1, 2, 3])

def gen_ioctl_request(arg_spec=None):
    """Generate ioctl request"""
    common = [0x5401, 0x5402, 0x5413, 0x5414, 0x540B, 0x541B]
    if random.random() < 0.5:
        return random.choice(common)
    return random.randint(0, 0xFFFFFFFF)

def gen_bpf_cmd(arg_spec=None):
    """Generate BPF command"""
    return random.randint(0, 30)

def gen_keyctl_cmd(arg_spec=None):
    """Generate keyctl command"""
    return random.randint(0, 25)

def gen_prctl_option(arg_spec=None):
    """Generate prctl option"""
    return random.choice([1, 2, 3, 4, 8, 15, 22, 23, 35, 38, 53])

def gen_mount_flags(arg_spec=None):
    """Generate mount flags"""
    flags = [0x1, 0x2, 0x4, 0x10, 0x20, 0x400, 0x1000]
    result = 0
    for _ in range(random.randint(0, 3)):
        result |= random.choice(flags)
    return result

def gen_splice_flags(arg_spec=None):
    """Generate splice flags"""
    return random.choice([0, 1, 2, 4, 8])

def gen_timer_flags(arg_spec=None):
    """Generate timer flags"""
    return random.choice([0, 1, 2])

def gen_clock_id(arg_spec=None):
    """Generate clock ID"""
    return random.choice([0, 1, 2, 3, 4, 5, 6, 7])

# Map type strings to generator functions
TYPE_GENERATORS = {
    "random_int": gen_random_int,
    "fd": gen_fd,
    "addr": gen_addr,
    "size": gen_size,
    "flags": gen_flags,
    "pid": gen_pid,
    "mode": gen_mode,
    "offset": gen_offset,
    "signal": gen_signal,
    "cpu": gen_cpu,
    
    # File operations
    "open_flags": gen_open_flags,
    "fcntl_cmd": gen_fcntl_cmd,
    
    # Memory
    "mmap_prot": gen_mmap_prot,
    "mmap_flags": gen_mmap_flags,
    "mmap_flags_cve": gen_mmap_flags_cve,
    
    # Network
    "socket_uaf": [
        {"action": "socket", "args": ["socket_domain", "socket_type", "socket_protocol"], "result": "sock_fd"},
        {"action": "close", "args": [{"value": "sock_fd"}]},
        {"action": "sendto", "args": [{"value": "sock_fd"}, "addr", "size", "flags", "addr", "size"]}
    ],
    
    "mmap_munmap_race": [
        {"action": "mmap", "args": ["addr", "size", "mmap_prot", "mmap_flags", "fd", "offset"], "result": "map_addr"},
        {"action": "munmap", "args": [{"value": "map_addr"}, "size"]},
        {"action": "mprotect", "args": [{"value": "map_addr"}, "size", "mmap_prot"]}
    ],
    
    "move_mount_panic": [
        {"action": "unshare", "args": ["flags"]},
        {"action": "mount", "args": ["addr", "addr", "addr", "mount_flags", "addr"]},
    ],
    
    "seccomp_ptrace_bypass": [
        {"action": "seccomp", "args": ["seccomp_flags", "flags", "addr"]},
        {"action": "ptrace", "args": ["ptrace_req_cve", "pid", "addr", "addr"]},
    ],
    
    "io_uring_race": [
        {"action": "io_uring_setup", "args": ["random_int", "addr"], "result": "ring_fd"},
        {"action": "io_uring_enter", "args": [{"value": "ring_fd"}, "random_int", "random_int", "flags", "addr", "size"]},
        {"action": "close", "args": [{"value": "ring_fd"}]},
        {"action": "io_uring_register", "args": [{"value": "ring_fd"}, "random_int", "addr", "random_int"]}
    ],
    
    "bpf_uaf": [
        {"action": "bpf", "args": ["bpf_cmd", "addr", "size"], "result": "bpf_fd"},
        {"action": "close", "args": [{"value": "bpf_fd"}]},
        {"action": "bpf", "args": ["bpf_cmd", {"value": "bpf_fd"}, "size"]}
    ],
    
    "userfaultfd_race": [
        {"action": "userfaultfd", "args": ["userfaultfd_flags"], "result": "uffd"},
        {"action": "ioctl", "args": [{"value": "uffd"}, "ioctl_request", "addr"]},
        {"action": "close", "args": [{"value": "uffd"}]}
    ],
    
    "timer_uaf": [
        {"action": "timer_create", "args": ["clock_id", "addr", "addr"], "result": "timer_id"},
        {"action": "timer_delete", "args": [{"value": "timer_id"}]},
        {"action": "timer_settime", "args": [{"value": "timer_id"}, "flags", "addr", "addr"]}
    ],
    
    "epoll_race": [
        {"action": "epoll_create1", "args": ["flags"], "result": "epoll_fd"},
        {"action": "open", "args": ["addr", "open_flags", "mode"], "result": "target_fd"},
        {"action": "epoll_ctl", "args": [{"value": "epoll_fd"}, "random_int", {"value": "target_fd"}, "addr"]},
        {"action": "close", "args": [{"value": "target_fd"}]},
        {"action": "epoll_wait", "args": [{"value": "epoll_fd"}, "addr", "random_int", "random_int"]}
    ],
    
    "splice_pipe_race": [
        {"action": "pipe", "args": ["addr"], "result": "pipe_fd"},
        {"action": "open", "args": ["addr", "open_flags", "mode"], "result": "file_fd"},
        {"action": "splice", "args": [{"value": "file_fd"}, "addr", {"value": "pipe_fd"}, "addr", "size", "splice_flags"]},
        {"action": "close", "args": [{"value": "pipe_fd"}]}
    ],
    
    "memfd_seal_bypass": [
        {"action": "memfd_create", "args": ["addr", "flags"], "result": "memfd"},
        {"action": "write", "args": [{"value": "memfd"}, "addr", "size"]},
        {"action": "fcntl", "args": [{"value": "memfd"}, "fcntl_cmd", "random_int"]},
        {"action": "ftruncate", "args": [{"value": "memfd"}, "size"]}
    ],
    "socket_domain": gen_socket_domain,
    "socket_type": gen_socket_type,
    "socket_protocol": gen_socket_protocol,
    "sockopt_level": gen_sockopt_level,
    
    # Process
    "clone_flags": gen_clone_flags,
    "wait_options": gen_wait_options,
    "prctl_option": gen_prctl_option,
    
    # I/O and events
    "epoll_events": gen_epoll_events,
    "poll_events": gen_poll_events,
    "splice_flags": gen_splice_flags,
    
    # Time
    "timer_flags": gen_timer_flags,
    "clock_id": gen_clock_id,
    
    # Advanced
    "ptrace_req_cve": gen_ptrace_req_cve,
    "userfaultfd_flags": gen_userfaultfd_flags,
    "seccomp_flags": gen_seccomp_flags,
    "ioctl_request": gen_ioctl_request,
    "bpf_cmd": gen_bpf_cmd,
    "keyctl_cmd": gen_keyctl_cmd,
    "mount_flags": gen_mount_flags,
}

# -----------------------
# Syscall Specifications (200+ syscalls)
# -----------------------
SYSCALL_SPECS = {
    # === Memory Management ===
    "mmap": ["addr", "size", "mmap_prot", "mmap_flags", "fd", "offset"],
    "munmap": ["addr", "size"],
    "mprotect": ["addr", "size", "mmap_prot"],
    "mremap": ["addr", "size", "size", "flags", "addr"],
    "msync": ["addr", "size", "flags"],
    "madvise": ["addr", "size", "random_int"],
    "mincore": ["addr", "size", "addr"],
    "mlock": ["addr", "size"],
    "munlock": ["addr", "size"],
    "mlockall": ["flags"],
    "munlockall": [],
    "brk": ["addr"],
    "memfd_create": ["addr", "flags"],
    "membarrier": ["random_int", "flags"],
    
    # === File Operations ===
    "open": ["addr", "open_flags", "mode"],
    "openat": ["fd", "addr", "open_flags", "mode"],
    "close": ["fd"],
    "read": ["fd", "addr", "size"],
    "write": ["fd", "addr", "size"],
    "readv": ["fd", "addr", "random_int"],
    "writev": ["fd", "addr", "random_int"],
    "pread64": ["fd", "addr", "size", "offset"],
    "pwrite64": ["fd", "addr", "size", "offset"],
    "preadv": ["fd", "addr", "random_int", "offset"],
    "pwritev": ["fd", "addr", "random_int", "offset"],
    "lseek": ["fd", "offset", "random_int"],
    "dup": ["fd"],
    "dup2": ["fd", "fd"],
    "dup3": ["fd", "fd", "flags"],
    "pipe": ["addr"],
    "pipe2": ["addr", "flags"],
    
    # === File Metadata ===
    "stat": ["addr", "addr"],
    "fstat": ["fd", "addr"],
    "lstat": ["addr", "addr"],
    "fstatat": ["fd", "addr", "addr", "flags"],
    "statx": ["fd", "addr", "flags", "random_int", "addr"],
    "access": ["addr", "flags"],
    "faccessat": ["fd", "addr", "flags"],
    "faccessat2": ["fd", "addr", "flags", "flags"],
    
    # === File Operations (Advanced) ===
    "fcntl": ["fd", "fcntl_cmd", "random_int"],
    "ioctl": ["fd", "ioctl_request", "addr"],
    "flock": ["fd", "random_int"],
    "fsync": ["fd"],
    "fdatasync": ["fd"],
    "sync": [],
    "truncate": ["addr", "size"],
    "ftruncate": ["fd", "size"],
    "fallocate": ["fd", "random_int", "offset", "size"],
    "sendfile": ["fd", "fd", "addr", "size"],
    "copy_file_range": ["fd", "addr", "fd", "addr", "size", "flags"],
    "splice": ["fd", "addr", "fd", "addr", "size", "splice_flags"],
    "vmsplice": ["fd", "addr", "random_int", "flags"],
    "tee": ["fd", "fd", "size", "flags"],
    
    # === Directory Operations ===
    "getcwd": ["addr", "size"],
    "chdir": ["addr"],
    "fchdir": ["fd"],
    "chroot": ["addr"],
    "mkdir": ["addr", "mode"],
    "mkdirat": ["fd", "addr", "mode"],
    "rmdir": ["addr"],
    "getdents64": ["fd", "addr", "size"],
    
    # === Link Operations ===
    "link": ["addr", "addr"],
    "linkat": ["fd", "addr", "fd", "addr", "flags"],
    "symlink": ["addr", "addr"],
    "symlinkat": ["addr", "fd", "addr"],
    "readlink": ["addr", "addr", "size"],
    "readlinkat": ["fd", "addr", "addr", "size"],
    "unlink": ["addr"],
    "unlinkat": ["fd", "addr", "flags"],
    "rename": ["addr", "addr"],
    "renameat": ["fd", "addr", "fd", "addr"],
    "renameat2": ["fd", "addr", "fd", "addr", "flags"],
    
    # === Permissions ===
    "chmod": ["addr", "mode"],
    "fchmod": ["fd", "mode"],
    "fchmodat": ["fd", "addr", "mode", "flags"],
    "chown": ["addr", "random_int", "random_int"],
    "fchown": ["fd", "random_int", "random_int"],
    "fchownat": ["fd", "addr", "random_int", "random_int", "flags"],
    "umask": ["mode"],
    
    # === Extended Attributes ===
    "setxattr": ["addr", "addr", "addr", "size", "flags"],
    "lsetxattr": ["addr", "addr", "addr", "size", "flags"],
    "fsetxattr": ["fd", "addr", "addr", "size", "flags"],
    "getxattr": ["addr", "addr", "addr", "size"],
    "lgetxattr": ["addr", "addr", "addr", "size"],
    "fgetxattr": ["fd", "addr", "addr", "size"],
    "listxattr": ["addr", "addr", "size"],
    "llistxattr": ["addr", "addr", "size"],
    "flistxattr": ["fd", "addr", "size"],
    "removexattr": ["addr", "addr"],
    "lremovexattr": ["addr", "addr"],
    "fremovexattr": ["fd", "addr"],
    
    # === Time Operations ===
    "utime": ["addr", "addr"],
    "utimes": ["addr", "addr"],
    "utimensat": ["fd", "addr", "addr", "flags"],
    "nanosleep": ["addr", "addr"],
    "clock_gettime": ["clock_id", "addr"],
    "clock_settime": ["clock_id", "addr"],
    "clock_getres": ["clock_id", "addr"],
    "clock_nanosleep": ["clock_id", "flags", "addr", "addr"],
    "gettimeofday": ["addr", "addr"],
    "settimeofday": ["addr", "addr"],
    "times": ["addr"],
    
    # === Timers ===
    "timer_create": ["clock_id", "addr", "addr"],
    "timer_settime": ["random_int", "flags", "addr", "addr"],
    "timer_gettime": ["random_int", "addr"],
    "timer_getoverrun": ["random_int"],
    "timer_delete": ["random_int"],
    "timerfd_create": ["clock_id", "flags"],
    "timerfd_settime": ["fd", "flags", "addr", "addr"],
    "timerfd_gettime": ["fd", "addr"],
    
    # === Process Management ===
    "fork": [],
    "vfork": [],
    "clone": ["clone_flags", "addr", "addr", "addr", "addr"],
    "clone3": ["addr", "size"],
    "execve": ["addr", "addr", "addr"],
    "execveat": ["fd", "addr", "addr", "addr", "flags"],
    "exit": ["random_int"],
    "exit_group": ["random_int"],
    "wait4": ["pid", "addr", "wait_options", "addr"],
    "waitid": ["random_int", "pid", "addr", "wait_options"],
    
    # === Process Info ===
    "getpid": [],
    "getppid": [],
    "gettid": [],
    "getuid": [],
    "geteuid": [],
    "getgid": [],
    "getegid": [],
    "getpgrp": [],
    "getpgid": ["pid"],
    "getsid": ["pid"],
    "setsid": [],
    "setpgid": ["pid", "pid"],
    
    # === Process Credentials ===
    "setuid": ["random_int"],
    "setgid": ["random_int"],
    "setreuid": ["random_int", "random_int"],
    "setregid": ["random_int", "random_int"],
    "setresuid": ["random_int", "random_int", "random_int"],
    "setresgid": ["random_int", "random_int", "random_int"],
    "getresuid": ["addr", "addr", "addr"],
    "getresgid": ["addr", "addr", "addr"],
    "getgroups": ["random_int", "addr"],
    "setgroups": ["random_int", "addr"],
    
    # === Process Control ===
    "prctl": ["prctl_option", "random_int", "random_int", "random_int", "random_int"],
    "setpriority": ["random_int", "random_int", "random_int"],
    "getpriority": ["random_int", "random_int"],
    "nice": ["random_int"],
    "sched_yield": [],
    "sched_setscheduler": ["pid", "random_int", "addr"],
    "sched_getscheduler": ["pid"],
    "sched_setparam": ["pid", "addr"],
    "sched_getparam": ["pid", "addr"],
    "sched_setaffinity": ["pid", "size", "addr"],
    "sched_getaffinity": ["pid", "size", "addr"],
    "prlimit64": ["pid", "random_int", "addr", "addr"],
    
    # === Signals ===
    "kill": ["pid", "signal"],
    "tkill": ["pid", "signal"],
    "tgkill": ["pid", "pid", "signal"],
    "rt_sigaction": ["signal", "addr", "addr", "size"],
    "rt_sigprocmask": ["random_int", "addr", "addr", "size"],
    "rt_sigsuspend": ["addr", "size"],
    "rt_sigqueueinfo": ["pid", "signal", "addr"],
    "rt_sigtimedwait": ["addr", "addr", "addr", "size"],
    "sigaltstack": ["addr", "addr"],
    "signalfd": ["fd", "addr", "size"],
    "signalfd4": ["fd", "addr", "size", "flags"],
    
    # === Networking - Sockets ===
    "socket": ["socket_domain", "socket_type", "socket_protocol"],
    "socketpair": ["socket_domain", "socket_type", "socket_protocol", "addr"],
    "connect": ["fd", "addr", "size"],
    "bind": ["fd", "addr", "size"],
    "listen": ["fd", "random_int"],
    "accept": ["fd", "addr", "addr"],
    "accept4": ["fd", "addr", "addr", "flags"],
    "getsockname": ["fd", "addr", "addr"],
    "getpeername": ["fd", "addr", "addr"],
    "shutdown": ["fd", "random_int"],
    
    # === Networking - I/O ===
    "sendto": ["fd", "addr", "size", "flags", "addr", "size"],
    "recvfrom": ["fd", "addr", "size", "flags", "addr", "addr"],
    "sendmsg": ["fd", "addr", "flags"],
    "recvmsg": ["fd", "addr", "flags"],
    "sendmmsg": ["fd", "addr", "random_int", "flags"],
    "recvmmsg": ["fd", "addr", "random_int", "flags", "addr"],
    
    # === Networking - Options ===
    "setsockopt": ["fd", "sockopt_level", "random_int", "addr", "size"],
    "getsockopt": ["fd", "sockopt_level", "random_int", "addr", "addr"],
    
    # === I/O Multiplexing ===
    "select": ["random_int", "addr", "addr", "addr", "addr"],
    "pselect6": ["random_int", "addr", "addr", "addr", "addr", "addr"],
    "poll": ["addr", "random_int", "random_int"],
    "ppoll": ["addr", "random_int", "addr", "addr"],
    "epoll_create": ["random_int"],
    "epoll_create1": ["flags"],
    "epoll_ctl": ["fd", "random_int", "fd", "addr"],
    "epoll_wait": ["fd", "addr", "random_int", "random_int"],
    "epoll_pwait": ["fd", "addr", "random_int", "random_int", "addr"],
    
    # === Event Notification ===
    "eventfd": ["random_int"],
    "eventfd2": ["random_int", "flags"],
    "inotify_init": [],
    "inotify_init1": ["flags"],
    "inotify_add_watch": ["fd", "addr", "random_int"],
    "inotify_rm_watch": ["fd", "random_int"],
    "fanotify_init": ["flags", "flags"],
    "fanotify_mark": ["fd", "flags", "random_int", "fd", "addr"],
    
    # === Futex ===
    "futex": ["addr", "random_int", "random_int", "addr", "addr", "random_int"],
    "set_robust_list": ["addr", "size"],
    "get_robust_list": ["pid", "addr", "addr"],
    "set_tid_address": ["addr"],
    
    # === System V IPC ===
    "shmget": ["random_int", "size", "flags"],
    "shmat": ["random_int", "addr", "flags"],
    "shmdt": ["addr"],
    "shmctl": ["random_int", "random_int", "addr"],
    "semget": ["random_int", "random_int", "flags"],
    "semop": ["random_int", "addr", "size"],
    "semctl": ["random_int", "random_int", "random_int", "addr"],
    "msgget": ["random_int", "flags"],
    "msgsnd": ["random_int", "addr", "size", "flags"],
    "msgrcv": ["random_int", "addr", "size", "random_int", "flags"],
    "msgctl": ["random_int", "random_int", "addr"],
    
    # === Special Files ===
    "mknod": ["addr", "mode", "random_int"],
    "mknodat": ["fd", "addr", "mode", "random_int"],
    
    # === Advanced/Kernel ===
    "ptrace": ["ptrace_req_cve", "pid", "addr", "addr"],
    "bpf": ["bpf_cmd", "addr", "size"],
    "keyctl": ["keyctl_cmd", "random_int", "random_int", "random_int", "random_int"],
    "userfaultfd": ["userfaultfd_flags"],
    "seccomp": ["seccomp_flags", "flags", "addr"],
    "perf_event_open": ["addr", "pid", "cpu", "fd", "flags"],
    "io_uring_setup": ["random_int", "addr"],
    "io_uring_enter": ["fd", "random_int", "random_int", "flags", "addr", "size"],
    "io_uring_register": ["fd", "random_int", "addr", "random_int"],
    
    # === Namespaces ===
    "unshare": ["flags"],
    "setns": ["fd", "flags"],
    "kcmp": ["pid", "pid", "random_int", "random_int", "random_int"],
    "pidfd_open": ["pid", "flags"],
    "pidfd_send_signal": ["fd", "signal", "addr", "flags"],
    "pidfd_getfd": ["fd", "fd", "flags"],
    
    # === Mount ===
    "mount": ["addr", "addr", "addr", "mount_flags", "addr"],
    "umount2": ["addr", "flags"],
    "pivot_root": ["addr", "addr"],
    
    # === Modules ===
    "init_module": ["addr", "size", "addr"],
    "finit_module": ["fd", "addr", "flags"],
    "delete_module": ["addr", "flags"],
    
    # === Capabilities ===
    "capget": ["addr", "addr"],
    "capset": ["addr", "addr"],
    
    # === System Info ===
    "uname": ["addr"],
    "sysinfo": ["addr"],
    "syslog": ["random_int", "addr", "size"],
    "getcpu": ["addr", "addr", "addr"],
    "getrandom": ["addr", "size", "flags"],
    
    # === Misc ===
    "ioperm": ["random_int", "random_int", "random_int"],
    "iopl": ["random_int"],
    "quotactl": ["random_int", "addr", "random_int", "addr"],
    "lookup_dcookie": ["random_int", "addr", "size"],
    "name_to_handle_at": ["fd", "addr", "addr", "addr", "flags"],
    "open_by_handle_at": ["fd", "addr", "flags"],
    "reboot": ["random_int", "random_int", "random_int", "addr"],
}

# -----------------------
# Syscall Sequences
# -----------------------
SYSCALL_SEQUENCES = {
    "uaf_double_close": [
        {"action": "open", "args": ["addr", "open_flags", "mode"], "result": "fd1"},
        {"action": "close", "args": [{"value": "fd1"}]},
        {"action": "close", "args": [{"value": "fd1"}]}
    ],
    
    "uaf_use_after_close": [
        {"action": "open", "args": ["addr", "open_flags", "mode"], "result": "fd1"},
        {"action": "close", "args": [{"value": "fd1"}]},
        {"action": "write", "args": [{"value": "fd1"}, "addr", "size"]}
    ],
    
    "race_dup_close": [
        {"action": "open", "args": ["addr", "open_flags", "mode"], "result": "fd1"},
        {"action": "dup", "args": [{"value": "fd1"}], "result": "fd2"},
        {"action": "close", "args": [{"value": "fd1"}]},
        {"action": "write", "args": [{"value": "fd2"}, "addr", "size"]}
    ],
    
    "pipe_uaf": [
        {"action": "pipe", "args": ["addr"], "result": "pipe_fd"},
        {"action": "close", "args": [{"value": "pipe_fd"}]},
        {"action": "write", "args": [{"value": "pipe_fd"}, "addr", "size"]}
    ],
    
}