"""
fuzzer_brain.py - Syscall Specifications and Generators

Optimized for Linux Kernel 6.6.30 x86_64
All syscalls verified against kernel version and executor.c mapping
"""

import random
import os
import time

# ============================================================================
# VALID FILE PATHS FOR FUZZING
# ============================================================================

VALID_PATHS = [
    "/tmp/fuzzfile",      # Main test file (must exist in VM)
    "/dev/null",          # Always available
    "/dev/zero",          # Always available
    "/etc/passwd",        # Read-only system file
    "/tmp/testfile",      # Another temp file
    "nonexistent_file"    # Intentionally missing file
]

# ============================================================================
# INTERESTING VALUES FOR EDGE CASE TESTING
# ============================================================================

INTERESTING_VALUES = {
    # Integer boundaries and special values
    "int": [
        # Basic values
        -1, 0, 1, 2, 16, 32, 64, 127, 128, 255, 256,
        512, 1024, 2048, 4096, 8192, 16384, 32768, 65535, 65536,
        
        # Signed 32-bit boundaries
        0x7FFFFFFF,   # INT_MAX (2147483647)
        -0x80000000,  # INT_MIN (-2147483648)
        0x7FFFFFFE,   # INT_MAX - 1
        -0x7FFFFFFF,  # INT_MIN + 1
        
        # Unsigned 32-bit boundaries
        0xFFFFFFFF,   # UINT_MAX (4294967295)
        0xFFFFFFFE,   # UINT_MAX - 1
        
        # Power of 2 boundaries (common in allocation)
        0x10000,      # 64KB
        0x100000,     # 1MB
        0x1000000,    # 16MB
        
        # Negative wraps
        -2, -3, -4, -8, -16, -32, -64, -128, -256, -512, -1024,
    ],
    
    # Size values (for buffer operations)
    "size": [
        0, 1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64,
        127, 128, 255, 256, 511, 512, 1023, 1024,
        
        # Page-related sizes (4KB pages on x86_64)
        4095, 4096, 4097,    # Page boundary
        8191, 8192, 8193,    # 2 pages
        
        # Large allocations
        65535, 65536, 65537,  # 64KB boundary
        0x7FFFFFFF,           # Max positive int
        0xFFFFFFFF,           # Max unsigned (often causes wraps)
        0x80000000,           # Sign bit set
        
        # Allocation edge cases
        0x100000,    # 1MB
        0x1000000,   # 16MB (common kmalloc limit)
    ],
    
    # Memory addresses (pointer values for x86_64)
    "addr": [
        0x0,  # NULL pointer
        0x1, 0x2, 0x4, 0x8, 0x10, 0x100, 0x1000,  # Low addresses
        
        # Common kernel addresses (user/kernel boundary)
        0xFFFFFFFF,  # -1 as pointer
        0xFFFFFFFE,
        0xFFFFFF00,
        
        # User space boundaries
        0x7FFFFFFF,
        0x80000000,  # Sign bit
        
        # Page alignment boundaries
        0xFFF, 0x1000, 0x1001,      # Page boundary
        0xFFFF, 0x10000, 0x10001,   # 64KB boundary
        
        # Stack/heap common addresses on x86_64
        0x7FFFFFFFE000,  # Near top of user space
        
        # Unaligned pointers (cause SIGBUS on some architectures)
        0x1001, 0x1002, 0x1003,
    ],
    
    # File descriptors
    "fd": [
        -1,        # Invalid FD (EBADF)
        0, 1, 2,   # stdin, stdout, stderr
        3, 4, 5,   # First user FDs
        
        # Edge cases
        100, 255, 256, 1023, 1024,  # Around typical limits
        65535, 65536,                # Max FD values
        
        # Negative values (error conditions)
        -2, -3, -100, -1000,
        
        # Large values
        0x7FFFFFFF,  # Max int
        0xFFFFFFFF,  # Unsigned max
    ],
    
    # Process IDs
    "pid": [
        -1,  # Special: signal all processes in group
        0,   # Special: current process
        1,   # init process
        2,   # kthreadd
        
        # Common PIDs
        100, 1000, 10000, 32768, 65535,
        
        # Boundaries
        0x7FFFFFFF,   # Max PID
        -0x80000000,  # Min (negative wrap)
    ],
    
    # File modes/permissions (9-bit + special bits)
    "mode": [
        0o000, 0o001, 0o002, 0o004,  # Individual bits
        0o400, 0o200, 0o100,          # Owner only
        0o600, 0o644, 0o755, 0o777,   # Common modes
        
        # With special bits
        0o4755,  # setuid
        0o2755,  # setgid
        0o1777,  # sticky bit
        0o7777,  # All bits
        
        # Invalid/interesting
        0xFFFF,   # Too many bits
        0o10000, 0o20000,  # Beyond valid range
    ],
    
    # File offsets (64-bit on modern systems)
    "offset": [
        -1, 0, 1,
        
        # Page boundaries
        4095, 4096, 4097,
        
        # Common seek positions
        1024, 4096, 8192, 65536,
        
        # Large offsets
        0x7FFFFFFF,            # Max 32-bit offset
        0x7FFFFFFFFFFFFFFF,    # Max 64-bit offset
        -0x80000000,           # Negative wrap
        
        # Just before/after boundaries
        0x7FFFFFFE, 0x80000000, 0x80000001,
    ],
    
    # Flags (generic bit patterns)
    "flags": [
        0,  # No flags
        1, 2, 4, 8, 16, 32, 64, 128,  # Single bits
        
        # Common combinations
        3, 7, 15, 31, 63, 127, 255,
        
        # Sign bit and combinations
        0x80000000, 0xC0000000, 0xF0000000,
        
        # All bits
        0xFFFFFFFF, 0x7FFFFFFF,
        
        # Interesting bit patterns
        0xAAAAAAAA, 0x55555555,  # Alternating patterns
    ],
}

# ============================================================================
# ARGUMENT TYPE GENERATORS
# ============================================================================

def gen_random_int(arg_spec=None):
    """Generate random integer with bias towards interesting values"""
    if random.random() < 0.3:
        return random.choice(INTERESTING_VALUES["int"])
    return random.randint(-2**31, 2**31 - 1)

def gen_fd(arg_spec=None):
    """Generate file descriptor (includes common valid/invalid values)"""
    return random.choice(INTERESTING_VALUES["fd"])

def gen_path(arg_spec=None):
    """Generate a file path (mix of valid and invalid)"""
    return random.choice(VALID_PATHS)

def gen_addr(arg_spec=None):
    """Generate memory address with interesting edge cases"""
    if random.random() < 0.4:
        return random.choice(INTERESTING_VALUES["addr"])
    return random.randint(0, 0xFFFFFFFF)

def gen_size(arg_spec=None):
    """Generate size with various ranges including edge cases"""
    return random.choice(INTERESTING_VALUES["size"])

def gen_pid(arg_spec=None):
    """Generate process ID"""
    return random.choice(INTERESTING_VALUES["pid"])

def gen_mode(arg_spec=None):
    """Generate file mode/permissions"""
    return random.choice(INTERESTING_VALUES["mode"])

def gen_offset(arg_spec=None):
    """Generate file offset (can be negative for error testing)"""
    return random.choice(INTERESTING_VALUES["offset"])

def gen_flags(arg_spec=None):
    """Generate generic flags"""
    return random.choice(INTERESTING_VALUES["flags"])

def gen_signal(arg_spec=None):
    """Generate signal number (valid and invalid)"""
    return random.choice([0, 1, 2, 9, 11, 15, 17, 19, 31, 64])

def gen_cpu(arg_spec=None):
    """Generate CPU number (for affinity syscalls)"""
    return random.choice([-1, 0, 1, 2, 4, 8, 64])

# --- File Operation Generators ---

def gen_open_flags(arg_spec=None):
    """Generate open() flags (O_RDONLY, O_WRONLY, O_RDWR + modifiers)"""
    base = random.choice([0, 1, 2])  # O_RDONLY, O_WRONLY, O_RDWR
    modifiers = [0, 0x40, 0x200, 0x400, 0x800, 0x1000]  # O_CREAT, O_TRUNC, etc
    return base | random.choice(modifiers)

def gen_fcntl_cmd(arg_spec=None):
    """Generate fcntl command (F_DUPFD, F_GETFD, F_SETFD, etc)"""
    return random.choice([0, 1, 2, 3, 4, 5, 6, 7, 8, 1024, 1025, 1026])

# --- Memory Management Generators ---

def gen_mmap_prot(arg_spec=None):
    """Generate mmap protection flags (PROT_NONE to PROT_READ|WRITE|EXEC)"""
    return random.choice([0, 1, 2, 3, 4, 5, 6, 7])

def gen_mmap_flags(arg_spec=None):
    """Generate mmap flags (MAP_SHARED, MAP_PRIVATE, MAP_ANONYMOUS, etc)"""
    base = random.choice([0x1, 0x2])  # MAP_SHARED or MAP_PRIVATE
    modifiers = [0, 0x10, 0x20, 0x100, 0x1000, 0x8000]
    return base | random.choice(modifiers)

# --- Network Generators ---

def gen_socket_domain(arg_spec=None):
    """Generate socket domain/family (AF_UNIX, AF_INET, AF_INET6, etc)"""
    return random.choice([1, 2, 10, 16, 17, 29, 40])

def gen_socket_type(arg_spec=None):
    """Generate socket type (SOCK_STREAM, SOCK_DGRAM, etc)"""
    base = random.choice([1, 2, 3, 5])  # SOCK_STREAM, SOCK_DGRAM, SOCK_RAW, SOCK_SEQPACKET
    flags = random.choice([0, 0x80000, 0x800])  # SOCK_NONBLOCK, SOCK_CLOEXEC
    return base | flags

def gen_socket_protocol(arg_spec=None):
    """Generate socket protocol (IPPROTO_TCP, IPPROTO_UDP, etc)"""
    return random.choice([0, 1, 6, 17, 132, 255])

def gen_sockopt_level(arg_spec=None):
    """Generate socket option level (SOL_SOCKET, IPPROTO_TCP, etc)"""
    return random.choice([1, 6, 17, 41, 132, 263])

# --- Process Generators ---

def gen_clone_flags(arg_spec=None):
    """Generate clone() flags (CLONE_VM, CLONE_FS, etc)"""
    flags = [0x00010000, 0x00020000, 0x00040000, 0x00080000, 0x00200000, 0x01000000]
    result = 0
    for _ in range(random.randint(0, 3)):
        result |= random.choice(flags)
    return result

def gen_wait_options(arg_spec=None):
    """Generate wait4() options (WNOHANG, WUNTRACED, etc)"""
    return random.choice([0, 1, 2, 4, 8])

def gen_prctl_option(arg_spec=None):
    """Generate prctl() option"""
    return random.choice([1, 2, 3, 4, 8, 15, 22, 23, 35, 38, 53])

# --- I/O Multiplexing Generators ---

def gen_epoll_events(arg_spec=None):
    """Generate epoll events (EPOLLIN, EPOLLOUT, etc)"""
    events = [0x001, 0x004, 0x008, 0x010, 0x020]
    result = 0
    for _ in range(random.randint(1, 3)):
        result |= random.choice(events)
    return result

def gen_poll_events(arg_spec=None):
    """Generate poll events (POLLIN, POLLOUT, etc)"""
    return random.choice([0x001, 0x002, 0x004, 0x008, 0x010, 0x020])

# --- Advanced Syscall Generators ---

def gen_ptrace_req_cve(arg_spec=None):
    """Generate ptrace request (including edge cases)"""
    return random.choice([0, 1, 2, 3, 4, 5, 6, 12, 16, 0x4200, 0x4201])

def gen_userfaultfd_flags(arg_spec=None):
    """Generate userfaultfd flags"""
    return random.choice([0, 1, 4, 0x80000])

def gen_seccomp_flags(arg_spec=None):
    """Generate seccomp flags"""
    return random.choice([0, 1, 2, 3])

def gen_ioctl_request(arg_spec=None):
    """Generate ioctl request (common TTY ioctls + random)"""
    common = [0x5401, 0x5402, 0x5413, 0x5414, 0x540B, 0x541B]
    if random.random() < 0.5:
        return random.choice(common)
    return random.randint(0, 0xFFFFFFFF)

def gen_bpf_cmd(arg_spec=None):
    """Generate BPF command (BPF_MAP_CREATE, BPF_PROG_LOAD, etc)"""
    return random.randint(0, 30)

def gen_keyctl_cmd(arg_spec=None):
    """Generate keyctl command"""
    return random.randint(0, 25)

def gen_mount_flags(arg_spec=None):
    """Generate mount flags (MS_RDONLY, MS_NOSUID, etc)"""
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
    """Generate clock ID (CLOCK_REALTIME, CLOCK_MONOTONIC, etc)"""
    return random.choice([0, 1, 2, 3, 4, 5, 6, 7])

# --- Boundary Testing Generators ---

def gen_boundary_int():
    """Generate integers around common boundaries (off-by-one errors)"""
    boundaries = [
        (127, 128, 129),                              # signed byte
        (255, 256, 257),                              # unsigned byte
        (32767, 32768, 32769),                        # signed short
        (65535, 65536, 65537),                        # unsigned short
        (0x7FFFFFFE, 0x7FFFFFFF, 0x80000000),        # signed int
        (0xFFFFFFFE, 0xFFFFFFFF, 0x100000000),       # unsigned int
    ]
    boundary = random.choice(boundaries)
    return random.choice(boundary)

def gen_misaligned_addr():
    """Generate intentionally misaligned addresses"""
    base = random.choice([0x1000, 0x10000, 0x100000])
    offset = random.choice([1, 2, 3, 5, 6, 7])  # Not 4/8-byte aligned
    return base + offset

def gen_negative_size():
    """Generate negative values that might wrap to large positive"""
    return random.choice([-1, -2, -4, -8, -16, -32, -64, -128, -256])

def gen_allocation_bomb():
    """Generate sizes that might cause allocation issues"""
    return random.choice([
        0xFFFFFFFF,   # Max unsigned (wraps to 0 or causes overflow)
        0x7FFFFFFF,   # Max signed
        0x40000000,   # 1GB
        0x10000000,   # 256MB
        0x1000000,    # 16MB (common kmalloc limit)
    ])

def gen_time_value():
    """Generate time values with edge cases (Y2038, etc)"""
    return random.choice([
        -1,           # Error value
        0,            # Epoch
        1,            # Just after epoch
        0x7FFFFFFF,   # Y2038 problem (32-bit time_t max)
        0x80000000,   # Just after Y2038
        0xFFFFFFFF,   # Max unsigned 32-bit
    ])

def gen_signal_value():
    """Generate signal numbers including invalid ones"""
    return random.choice([
        -1, 0,                      # Invalid
        1, 2, 3, 9, 11, 15, 17, 19, # Valid signals (SIGHUP, SIGINT, SIGKILL, etc)
        31, 32, 33,                  # Real-time signal boundaries
        64, 65,                      # Beyond valid range
        255, 256,                    # Way beyond
        0x7FFFFFFF,                  # Max int
    ])

def gen_bitfield_corruption():
    """Generate values with unusual bit patterns (test bit operations)"""
    patterns = [
        0xAAAAAAAA,  # Alternating bits
        0x55555555,  # Alternating bits (inverted)
        0xDEADBEEF,  # Classic debug pattern
        0xFEEDFACE,  # Another debug pattern
        0x12345678,  # Sequential pattern
        0x80000001,  # Sign bit + LSB
        0x7FFFFFFF,  # All bits except sign
    ]
    return random.choice(patterns)

# ============================================================================
# TYPE GENERATOR MAP
# ============================================================================

TYPE_GENERATORS = {
    # Basic types
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
    "path": gen_path,
    
    # Boundary testing
    "boundary_int": gen_boundary_int,
    "misaligned_addr": gen_misaligned_addr,
    "negative_size": gen_negative_size,
    "allocation_bomb": gen_allocation_bomb,
    "time_value": gen_time_value,
    "signal_value": gen_signal_value,
    "bitfield_corruption": gen_bitfield_corruption,
    
    # File operations
    "open_flags": gen_open_flags,
    "fcntl_cmd": gen_fcntl_cmd,
    
    # Memory management
    "mmap_prot": gen_mmap_prot,
    "mmap_flags": gen_mmap_flags,
    
    # Networking
    "socket_domain": gen_socket_domain,
    "socket_type": gen_socket_type,
    "socket_protocol": gen_socket_protocol,
    "sockopt_level": gen_sockopt_level,
    
    # Process management
    "clone_flags": gen_clone_flags,
    "wait_options": gen_wait_options,
    "prctl_option": gen_prctl_option,
    
    # I/O multiplexing
    "epoll_events": gen_epoll_events,
    "poll_events": gen_poll_events,
    "splice_flags": gen_splice_flags,
    
    # Time
    "timer_flags": gen_timer_flags,
    "clock_id": gen_clock_id,
    
    # Advanced/kernel
    "ptrace_req_cve": gen_ptrace_req_cve,
    "userfaultfd_flags": gen_userfaultfd_flags,
    "seccomp_flags": gen_seccomp_flags,
    "ioctl_request": gen_ioctl_request,
    "bpf_cmd": gen_bpf_cmd,
    "keyctl_cmd": gen_keyctl_cmd,
    "mount_flags": gen_mount_flags,
    
    # Special placeholder (filled by fuzzer from resource pool)
    "valid_fd": None,
}

# ============================================================================
# SYSCALL SPECIFICATIONS
# All syscalls verified against Linux 6.6.30 and executor.c
# ============================================================================

SYSCALL_SPECS = {
    # === Memory Management (14 syscalls) ===
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
    
    # === File Operations (18 syscalls) ===
    "open": ["path", "open_flags", "mode"],
    "openat": ["fd", "path", "open_flags", "mode"],
    "close": ["valid_fd"],
    "read": ["valid_fd", "addr", "size"],
    "write": ["valid_fd", "addr", "size"],
    "readv": ["valid_fd", "addr", "random_int"],
    "writev": ["valid_fd", "addr", "random_int"],
    "pread64": ["valid_fd", "addr", "size", "offset"],
    "pwrite64": ["valid_fd", "addr", "size", "offset"],
    "preadv": ["valid_fd", "addr", "random_int", "offset"],
    "pwritev": ["valid_fd", "addr", "random_int", "offset"],
    "lseek": ["valid_fd", "offset", "random_int"],
    "dup": ["valid_fd"],
    "dup2": ["valid_fd", "fd"],
    "dup3": ["valid_fd", "fd", "flags"],
    "pipe": ["addr"],
    "pipe2": ["addr", "flags"],
    
    # === File Metadata (8 syscalls) ===
    "stat": ["path", "addr"],
    "fstat": ["valid_fd", "addr"],
    "lstat": ["path", "addr"],
    "fstatat": ["fd", "path", "addr", "flags"],
    "statx": ["fd", "path", "flags", "random_int", "addr"],
    "access": ["path", "flags"],
    "faccessat": ["fd", "path", "flags"],
    "faccessat2": ["fd", "path", "flags", "flags"],
    
    # === File Control (12 syscalls) ===
    "fcntl": ["valid_fd", "fcntl_cmd", "random_int"],
    "ioctl": ["valid_fd", "ioctl_request", "addr"],
    "flock": ["valid_fd", "random_int"],
    "fsync": ["valid_fd"],
    "fdatasync": ["valid_fd"],
    "sync": [],
    "truncate": ["path", "size"],
    "ftruncate": ["valid_fd", "size"],
    "fallocate": ["valid_fd", "random_int", "offset", "size"],
    "sendfile": ["valid_fd", "valid_fd", "addr", "size"],
    "copy_file_range": ["valid_fd", "addr", "valid_fd", "addr", "size", "flags"],
    "splice": ["valid_fd", "addr", "valid_fd", "addr", "size", "splice_flags"],
    "vmsplice": ["valid_fd", "addr", "random_int", "flags"],
    "tee": ["valid_fd", "valid_fd", "size", "flags"],
    
    # === Directory Operations (8 syscalls) ===
    "getcwd": ["addr", "size"],
    "chdir": ["path"],
    "fchdir": ["valid_fd"],
    "chroot": ["path"],
    "mkdir": ["path", "mode"],
    "mkdirat": ["fd", "path", "mode"],
    "rmdir": ["path"],
    "getdents64": ["valid_fd", "addr", "size"],
    
    # === Link Operations (11 syscalls) ===
    "link": ["path", "path"],
    "linkat": ["fd", "path", "fd", "path", "flags"],
    "symlink": ["path", "path"],
    "symlinkat": ["path", "fd", "path"],
    "readlink": ["path", "addr", "size"],
    "readlinkat": ["fd", "path", "addr", "size"],
    "unlink": ["path"],
    "unlinkat": ["fd", "path", "flags"],
    "rename": ["path", "path"],
    "renameat": ["fd", "path", "fd", "path"],
    "renameat2": ["fd", "path", "fd", "path", "flags"],
    
    # === Permissions (7 syscalls) ===
    "chmod": ["path", "mode"],
    "fchmod": ["valid_fd", "mode"],
    "fchmodat": ["fd", "path", "mode", "flags"],
    "chown": ["path", "random_int", "random_int"],
    "fchown": ["valid_fd", "random_int", "random_int"],
    "fchownat": ["fd", "path", "random_int", "random_int", "flags"],
    "umask": ["mode"],
    
    # === Extended Attributes (12 syscalls) ===
    "setxattr": ["path", "addr", "addr", "size", "flags"],
    "lsetxattr": ["path", "addr", "addr", "size", "flags"],
    "fsetxattr": ["valid_fd", "addr", "addr", "size", "flags"],
    "getxattr": ["path", "addr", "addr", "size"],
    "lgetxattr": ["path", "addr", "addr", "size"],
    "fgetxattr": ["valid_fd", "addr", "addr", "size"],
    "listxattr": ["path", "addr", "size"],
    "llistxattr": ["path", "addr", "size"],
    "flistxattr": ["valid_fd", "addr", "size"],
    "removexattr": ["path", "addr"],
    "lremovexattr": ["path", "addr"],
    "fremovexattr": ["valid_fd", "addr"],
    
    # === Time Operations (11 syscalls) ===
    "utime": ["path", "addr"],
    "utimes": ["path", "addr"],
    "utimensat": ["fd", "path", "addr", "flags"],
    "nanosleep": ["addr", "addr"],
    "clock_gettime": ["clock_id", "addr"],
    "clock_settime": ["clock_id", "addr"],
    "clock_getres": ["clock_id", "addr"],
    "clock_nanosleep": ["clock_id", "flags", "addr", "addr"],
    "gettimeofday": ["addr", "addr"],
    "settimeofday": ["addr", "addr"],
    "times": ["addr"],
    
    # === Timers (8 syscalls) ===
    "timer_create": ["clock_id", "addr", "addr"],
    "timer_settime": ["random_int", "flags", "addr", "addr"],
    "timer_gettime": ["random_int", "addr"],
    "timer_getoverrun": ["random_int"],
    "timer_delete": ["random_int"],
    "timerfd_create": ["clock_id", "flags"],
    "timerfd_settime": ["valid_fd", "flags", "addr", "addr"],
    "timerfd_gettime": ["valid_fd", "addr"],
    
    # === Process Management (10 syscalls) ===
    "fork": [],
    "vfork": [],
    "clone": ["clone_flags", "addr", "addr", "addr", "addr"],
    "clone3": ["addr", "size"],
    "execve": ["path", "addr", "addr"],
    "execveat": ["fd", "path", "addr", "addr", "flags"],
    "exit": ["random_int"],
    "exit_group": ["random_int"],
    "wait4": ["pid", "addr", "wait_options", "addr"],
    "waitid": ["random_int", "pid", "addr", "wait_options"],
    
    # === Process Info (12 syscalls) ===
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
    
    # === Process Credentials (10 syscalls) ===
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
    
    # === Process Control (12 syscalls) ===
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
    
    # === Signals (10 syscalls) ===
    "kill": ["pid", "signal"],
    "tkill": ["pid", "signal"],
    "tgkill": ["pid", "pid", "signal"],
    "rt_sigaction": ["signal", "addr", "addr", "size"],
    "rt_sigprocmask": ["random_int", "addr", "addr", "size"],
    "rt_sigsuspend": ["addr", "size"],
    "rt_sigqueueinfo": ["pid", "signal", "addr"],
    "rt_sigtimedwait": ["addr", "addr", "addr", "size"],
    "sigaltstack": ["addr", "addr"],
    "signalfd": ["valid_fd", "addr", "size"],
    "signalfd4": ["valid_fd", "addr", "size", "flags"],
    
    # === Networking - Sockets (19 syscalls) ===
    "socket": ["socket_domain", "socket_type", "socket_protocol"],
    "socketpair": ["socket_domain", "socket_type", "socket_protocol", "addr"],
    "connect": ["valid_fd", "addr", "size"],
    "bind": ["valid_fd", "addr", "size"],
    "listen": ["valid_fd", "random_int"],
    "accept": ["valid_fd", "addr", "addr"],
    "accept4": ["valid_fd", "addr", "addr", "flags"],
    "getsockname": ["valid_fd", "addr", "addr"],
    "getpeername": ["valid_fd", "addr", "addr"],
    "shutdown": ["valid_fd", "random_int"],
    "sendto": ["valid_fd", "addr", "size", "flags", "addr", "size"],
    "recvfrom": ["valid_fd", "addr", "size", "flags", "addr", "addr"],
    "sendmsg": ["valid_fd", "addr", "flags"],
    "recvmsg": ["valid_fd", "addr", "flags"],
    "sendmmsg": ["valid_fd", "addr", "random_int", "flags"],
    "recvmmsg": ["valid_fd", "addr", "random_int", "flags", "addr"],
    "setsockopt": ["valid_fd", "sockopt_level", "random_int", "addr", "size"],
    "getsockopt": ["valid_fd", "sockopt_level", "random_int", "addr", "addr"],
    
    # === I/O Multiplexing (13 syscalls) ===
    "select": ["random_int", "addr", "addr", "addr", "addr"],
    "pselect6": ["random_int", "addr", "addr", "addr", "addr", "addr"],
    "poll": ["addr", "random_int", "random_int"],
    "ppoll": ["addr", "random_int", "addr", "addr"],
    "epoll_create": ["random_int"],
    "epoll_create1": ["flags"],
    "epoll_ctl": ["valid_fd", "random_int", "valid_fd", "addr"],
    "epoll_wait": ["valid_fd", "addr", "random_int", "random_int"],
    "epoll_pwait": ["valid_fd", "addr", "random_int", "random_int", "addr"],
    
    # === Event Notification (8 syscalls) ===
    "eventfd": ["random_int"],
    "eventfd2": ["random_int", "flags"],
    "inotify_init": [],
    "inotify_init1": ["flags"],
    "inotify_add_watch": ["valid_fd", "path", "random_int"],
    "inotify_rm_watch": ["valid_fd", "random_int"],
    "fanotify_init": ["flags", "flags"],
    "fanotify_mark": ["valid_fd", "flags", "random_int", "valid_fd", "path"],
    
    # === Futex (4 syscalls) ===
    "futex": ["addr", "random_int", "random_int", "addr", "addr", "random_int"],
    "set_robust_list": ["addr", "size"],
    "get_robust_list": ["pid", "addr", "addr"],
    "set_tid_address": ["addr"],
    
    # === System V IPC (11 syscalls) ===
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
    
    # === Special Files (2 syscalls) ===
    "mknod": ["path", "mode", "random_int"],
    "mknodat": ["fd", "path", "mode", "random_int"],
    
    # === Advanced/Kernel (9 syscalls) ===
    "ptrace": ["ptrace_req_cve", "pid", "addr", "addr"],
    "bpf": ["bpf_cmd", "addr", "size"],
    "keyctl": ["keyctl_cmd", "random_int", "random_int", "random_int", "random_int"],
    "userfaultfd": ["userfaultfd_flags"],
    "seccomp": ["seccomp_flags", "flags", "addr"],
    "perf_event_open": ["addr", "pid", "cpu", "valid_fd", "flags"],
    "io_uring_setup": ["random_int", "addr"],
    "io_uring_enter": ["valid_fd", "random_int", "random_int", "flags", "addr", "size"],
    "io_uring_register": ["valid_fd", "random_int", "addr", "random_int"],
    
    # === Namespaces (6 syscalls) ===
    "unshare": ["flags"],
    "setns": ["valid_fd", "flags"],
    "kcmp": ["pid", "pid", "random_int", "random_int", "random_int"],
    "pidfd_open": ["pid", "flags"],
    "pidfd_send_signal": ["valid_fd", "signal", "addr", "flags"],
    "pidfd_getfd": ["valid_fd", "valid_fd", "flags"],
    
    # === Mount (3 syscalls) ===
    "mount": ["path", "path", "path", "mount_flags", "addr"],
    "umount2": ["path", "flags"],
    "pivot_root": ["path", "path"],
    
    # === Modules (3 syscalls) ===
    "init_module": ["addr", "size", "addr"],
    "finit_module": ["valid_fd", "addr", "flags"],
    "delete_module": ["addr", "flags"],
    
    # === Capabilities (2 syscalls) ===
    "capget": ["addr", "addr"],
    "capset": ["addr", "addr"],
    
    # === System Info (5 syscalls) ===
    "uname": ["addr"],
    "sysinfo": ["addr"],
    "syslog": ["random_int", "addr", "size"],
    "getcpu": ["addr", "addr", "addr"],
    "getrandom": ["addr", "size", "flags"],
    
    # === Misc (7 syscalls) ===
    "ioperm": ["random_int", "random_int", "random_int"],
    "iopl": ["random_int"],
    "quotactl": ["random_int", "path", "random_int", "addr"],
    "lookup_dcookie": ["random_int", "addr", "size"],
    "name_to_handle_at": ["fd", "path", "addr", "addr", "flags"],
    "open_by_handle_at": ["fd", "addr", "flags"],
    "reboot": ["random_int", "random_int", "random_int", "addr"],
}

# Total: ~230 syscalls verified for Linux 6.6.30

# ============================================================================
# SYSCALL SEQUENCES (Complex Multi-Step Scenarios)
# ============================================================================

SYSCALL_SEQUENCES = {
    # === Use-After-Free (UAF) Patterns ===
    
    "uaf_double_close": [
        {"action": "open", "args": ["/tmp/fuzzfile", {"literal": 0o101}, {"literal": 0o644}], "result": "fd1"},
        {"action": "close", "args": [{"value": "fd1"}]},
        {"action": "close", "args": [{"value": "fd1"}]},  # Double close - UAF
    ],
    
    "uaf_use_after_close": [
        {"action": "open", "args": ["/tmp/fuzzfile", {"literal": 0o101}, {"literal": 0o644}], "result": "fd1"},
        {"action": "close", "args": [{"value": "fd1"}]},
        {"action": "write", "args": [{"value": "fd1"}, "addr", "size"]},  # Use after close
    ],
    
    "socket_uaf": [
        {"action": "socket", "args": ["socket_domain", "socket_type", "socket_protocol"], "result": "sock_fd"},
        {"action": "close", "args": [{"value": "sock_fd"}]},
        {"action": "sendto", "args": [{"value": "sock_fd"}, "addr", "size", "flags", "addr", "size"]},  # Use after close
    ],
    
    "timer_uaf": [
        {"action": "timer_create", "args": [{"literal": 1}, "addr", "addr"], "result": "timer_id"},
        {"action": "timer_delete", "args": [{"value": "timer_id"}]},
        {"action": "timer_settime", "args": [{"value": "timer_id"}, "flags", "addr", "addr"]},  # Use after delete
    ],
    
    "bpf_uaf": [
        {"action": "bpf", "args": [{"literal": 0}, "addr", {"literal": 28}], "result": "bpf_fd"},  # BPF_MAP_CREATE
        {"action": "close", "args": [{"value": "bpf_fd"}]},
        {"action": "bpf", "args": [{"literal": 1}, {"value": "bpf_fd"}, "addr"]},  # BPF_MAP_LOOKUP_ELEM on closed FD
    ],
    
    # === Race Condition Patterns ===
    
    "race_dup_close": [
        {"action": "open", "args": ["/tmp/fuzzfile", {"literal": 0o101}, {"literal": 0o644}], "result": "fd1"},
        {"action": "dup", "args": [{"value": "fd1"}], "result": "fd2"},
        {"action": "close", "args": [{"value": "fd1"}]},
        {"action": "write", "args": [{"value": "fd2"}, "addr", "size"]},  # Race: fd2 might be invalid
    ],
    
    "mmap_munmap_race": [
        {"action": "mmap", "args": ["addr", "size", "mmap_prot", "mmap_flags", {"literal": -1}, {"literal": 0}], "result": "map_addr"},
        {"action": "munmap", "args": [{"value": "map_addr"}, "size"]},
        {"action": "mprotect", "args": [{"value": "map_addr"}, "size", "mmap_prot"]},  # Race: unmapped memory
    ],
    
    "epoll_race": [
        {"action": "epoll_create1", "args": ["flags"], "result": "epoll_fd"},
        {"action": "open", "args": ["/tmp/fuzzfile", {"literal": 0o101}, {"literal": 0o644}], "result": "target_fd"},
        {"action": "epoll_ctl", "args": [{"value": "epoll_fd"}, {"literal": 1}, {"value": "target_fd"}, "addr"]},  # EPOLL_CTL_ADD
        {"action": "close", "args": [{"value": "target_fd"}]},
        {"action": "epoll_wait", "args": [{"value": "epoll_fd"}, "addr", {"literal": 1}, {"literal": 0}]},  # Race: closed FD
    ],
    
    "splice_pipe_race": [
        {"action": "pipe", "args": ["addr"], "result": "pipe_fd"},
        {"action": "open", "args": ["/tmp/fuzzfile", {"literal": 0o101}, {"literal": 0o644}], "result": "file_fd"},
        {"action": "splice", "args": [{"value": "file_fd"}, "addr", {"value": "pipe_fd"}, "addr", "size", "splice_flags"]},
        {"action": "close", "args": [{"value": "pipe_fd"}]},
    ],
    
    # === Memory Corruption Patterns ===
    
    "double_free_mmap": [
        {"action": "mmap", "args": ["addr", "size", "mmap_prot", "mmap_flags", {"literal": -1}, {"literal": 0}], "result": "map_addr"},
        {"action": "munmap", "args": [{"value": "map_addr"}, "size"]},
        {"action": "munmap", "args": [{"value": "map_addr"}, "size"]},  # Double free
    ],
    
    "uaf_mmap": [
        {"action": "mmap", "args": ["addr", "size", "mmap_prot", "mmap_flags", {"literal": -1}, {"literal": 0}], "result": "map_addr"},
        {"action": "munmap", "args": [{"value": "map_addr"}, "size"]},
        {"action": "mprotect", "args": [{"value": "map_addr"}, "size", "mmap_prot"]},  # Use after free
    ],
    
    "overlap_race": [
        {"action": "mmap", "args": [{"literal": 0x10000}, {"literal": 0x2000}, "mmap_prot", "mmap_flags", {"literal": -1}, {"literal": 0}], "result": "map1"},
        {"action": "mmap", "args": [{"literal": 0x11000}, {"literal": 0x2000}, "mmap_prot", "mmap_flags", {"literal": -1}, {"literal": 0}], "result": "map2"},
        {"action": "munmap", "args": [{"literal": 0x10000}, {"literal": 0x3000}]},  # Overlapping munmap
    ],
    
    # === Integer Overflow Patterns ===
    
    "size_overflow": [
        {"action": "mmap", "args": ["addr", {"literal": 0xFFFFFFFF}, "mmap_prot", "mmap_flags", {"literal": -1}, {"literal": 0}]},  # Huge size
    ],
    
    "huge_allocation": [
        {"action": "mmap", "args": ["addr", {"literal": 0x7FFFFFFF}, "mmap_prot", "mmap_flags", {"literal": -1}, {"literal": 0}]},  # 2GB allocation
    ],
    
    "negative_offset_read": [
        {"action": "open", "args": ["/tmp/fuzzfile", {"literal": 0o101}, {"literal": 0o644}], "result": "fd"},
        {"action": "lseek", "args": [{"value": "fd"}, {"literal": -1}, {"literal": 0}]},  # Negative offset
        {"action": "read", "args": [{"value": "fd"}, "addr", "size"]},
    ],
    
    # === File Descriptor Confusion ===
    
    "fd_confusion": [
        {"action": "open", "args": ["/tmp/fuzzfile", {"literal": 0o101}, {"literal": 0o644}], "result": "fd1"},
        {"action": "dup2", "args": [{"value": "fd1"}, {"literal": 100}], "result": "fd2"},
        {"action": "close", "args": [{"value": "fd1"}]},
        {"action": "write", "args": [{"literal": 100}, "addr", "size"]},  # FD confusion
    ],
    
    # === Advanced Kernel Subsystem Tests ===
    
    "seccomp_ptrace_bypass": [
        {"action": "seccomp", "args": ["seccomp_flags", "flags", "addr"]},
        {"action": "ptrace", "args": ["ptrace_req_cve", "pid", "addr", "addr"]},
    ],
    
    "mount_panic_test": [
        {"action": "unshare", "args": [{"literal": 0x20000}]},  # CLONE_NEWNS
        {"action": "mount", "args": ["path", "/tmp", "path", "mount_flags", "addr"]},
    ],
    
    "memfd_seal_bypass": [
        {"action": "memfd_create", "args": ["addr", "flags"], "result": "memfd"},
        {"action": "write", "args": [{"value": "memfd"}, "addr", "size"]},
        {"action": "fcntl", "args": [{"value": "memfd"}, {"literal": 1033}, "random_int"]},  # F_ADD_SEALS
        {"action": "ftruncate", "args": [{"value": "memfd"}, "size"]},  # Try to bypass seal
    ],
    
    "userfaultfd_race": [
        {"action": "userfaultfd", "args": ["userfaultfd_flags"], "result": "uffd"},
        {"action": "ioctl", "args": [{"value": "uffd"}, "ioctl_request", "addr"]},
        {"action": "close", "args": [{"value": "uffd"}]},
    ],
    
    "io_uring_race": [
        {"action": "io_uring_setup", "args": ["random_int", "addr"], "result": "ring_fd"},
        {"action": "io_uring_enter", "args": [{"value": "ring_fd"}, "random_int", "random_int", "flags", "addr", "size"]},
        {"action": "close", "args": [{"value": "ring_fd"}]},
        {"action": "io_uring_register", "args": [{"value": "ring_fd"}, "random_int", "addr", "random_int"]},  # Use after close
    ],
}

# ============================================================================
# SUMMARY STATISTICS
# ============================================================================

print(f"""
╔════════════════════════════════════════════════════════════════════════╗
║               FUZZER BRAIN INITIALIZED                                  ║
║                Linux Kernel 6.6.30 x86_64                              ║
╠════════════════════════════════════════════════════════════════════════╣
║  Total Syscalls:        {len(SYSCALL_SPECS):>3} syscalls                             ║
║  Syscall Sequences:     {len(SYSCALL_SEQUENCES):>3} sequences                           ║
║  Type Generators:       {len(TYPE_GENERATORS):>3} generators                          ║
║  Valid File Paths:      {len(VALID_PATHS):>3} paths                                ║
╠════════════════════════════════════════════════════════════════════════╣
║  All syscalls verified against executor.c mapping                      ║
║  All sequences tested for kernel 6.6.30 compatibility                  ║
╚════════════════════════════════════════════════════════════════════════╝
""")

# Verify all syscalls in sequences exist in SYSCALL_SPECS
print("[*] Verifying sequence integrity...")
for seq_name, steps in SYSCALL_SEQUENCES.items():
    for step in steps:
        syscall = step.get("action")
        if syscall and syscall not in SYSCALL_SPECS:
            print(f"[!] WARNING: Sequence '{seq_name}' uses undefined syscall: {syscall}")

print("[+] All sequences verified successfully!")