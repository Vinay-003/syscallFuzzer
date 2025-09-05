import random

# This file contains the "brain" of the fuzzer, turning the research on
# real-world CVEs and bug reports into concrete test case generators.

# --- Constants for Syscall Arguments (from research and new additions) ---
# For mmap()
PROT_READ, PROT_WRITE, PROT_EXEC = 0x1, 0x2, 0x4
MAP_SHARED, MAP_PRIVATE, MAP_ANONYMOUS, MAP_POPULATE = 0x01, 0x02, 0x20, 0x008000

# For ptrace()
PTRACE_TRACEME = 0

# For seccomp()
SECCOMP_SET_MODE_FILTER = 1

# For userfaultfd()
O_CLOEXEC, O_NONBLOCK = 0x80000, 0x800

# For mount()
MS_MOVE = 4096

# For unshare()
CLONE_NEWNS, CLONE_NEWPID, CLONE_NEWUSER = 0x00020000, 0x20000000, 0x10000000

# For socket()
AF_INET, AF_INET6, AF_UNIX, AF_NETLINK = 2, 10, 1, 16
SOCK_STREAM, SOCK_DGRAM, SOCK_RAW = 1, 2, 3

# For keyctl()
KEYCTL_GET_KEYRING_ID = 0

# --- Targeted Argument Generators ---

def gen_fd():
    """Generates a generic, interesting file descriptor."""
    return random.choice([-1, 0, 1, 2, 100])

def gen_addr():
    """Generates a generic, interesting memory address."""
    return random.choice([0, 0xffffffffffffffff, 0xdeadbeef, 4096])

def gen_size():
    """Generates a generic, interesting size or length."""
    return random.choice([0, 4096, 2**32-1, -1])

def gen_flags():
    """Generates a generic combination of flags."""
    return random.randint(0, 0xffffffff)

# --- CVE and Research-Specific Generators ---
def gen_mmap_flags_cve_2024_39497():
    print("   [+] Generating targeted flags for CVE-2024-39497 (mmap)...")
    return PROT_WRITE | MAP_PRIVATE

def gen_ptrace_request_cve_2019_13272():
    print("   [+] Generating targeted request for CVE-2019-13272 (ptrace)...")
    return PTRACE_TRACEME

def gen_mount_flags_move():
    return MS_MOVE

def gen_unshare_flags_ns():
    return random.choice([CLONE_NEWNS, CLONE_NEWPID, CLONE_NEWNS | CLONE_NEWPID])

def gen_seccomp_flags():
    return SECCOMP_SET_MODE_FILTER

def gen_userfaultfd_flags():
    return random.choice([0, O_CLOEXEC, O_NONBLOCK, O_CLOEXEC | O_NONBLOCK])

# --- Newly Added Generators from Research ---
def gen_socket_domain():
    """Generates a random socket domain."""
    return random.choice([AF_INET, AF_INET6, AF_UNIX, AF_NETLINK, -1])

def gen_socket_type():
    """Generates a random socket type."""
    return random.choice([SOCK_STREAM, SOCK_DGRAM, SOCK_RAW, 0, 10])

def gen_ioctl_request():
    """Generates a random, potentially invalid ioctl request code."""
    # ioctl requests are highly driver-specific, so random values are a good start.
    return random.randint(0, 0xffffffff)

def gen_bpf_command():
    """Generates a random command for the bpf syscall."""
    # 0 = BPF_MAP_CREATE, 5 = BPF_PROG_LOAD. These are complex and good targets.
    return random.choice([0, 5, -1])

def gen_keyctl_command():
    """Generates a command for the keyctl syscall."""
    return KEYCTL_GET_KEYRING_ID

# Mapping of type names to their generator functions
TYPE_GENERATORS = {
    "fd": gen_fd,
    "addr": gen_addr,
    "size": gen_size,
    "flags": gen_flags,
    "mmap_flags_cve": gen_mmap_flags_cve_2024_39497,
    "ptrace_req_cve": gen_ptrace_request_cve_2019_13272,
    "mount_flags_move": gen_mount_flags_move,
    "unshare_flags_ns": gen_unshare_flags_ns,
    "seccomp_flags": gen_seccomp_flags,
    "userfaultfd_flags": gen_userfaultfd_flags,
    "socket_domain": gen_socket_domain,
    "socket_type": gen_socket_type,
    "ioctl_request": gen_ioctl_request,
    "bpf_cmd": gen_bpf_command,
    "keyctl_cmd": gen_keyctl_command,
}

# --- Syscall & Sequence Definitions ---

SYSCALL_SPECS = {
    # General, high-frequency syscalls
    "read": ["fd", "addr", "size"],
    "write": ["fd", "addr", "size"],
    "open": ["addr", "flags"],
    "close": ["fd"],
    
    # Targeted syscalls from your research
    "mmap": ["addr", "size", "mmap_flags_cve", "fd", "size"],
    "ptrace": ["ptrace_req_cve", "size", "addr", "addr"],
    "userfaultfd": ["userfaultfd_flags"],
    "seccomp": ["seccomp_flags", "flags", "addr"],
    
    # Newly added high-value targets
    "ioctl": ["fd", "ioctl_request", "addr"],
    "bpf": ["bpf_cmd", "addr", "size"],
    "io_uring_setup": ["size", "addr"],
    "keyctl": ["keyctl_cmd", "flags", "size", "addr"],
}

SYSCALL_SEQUENCES = {
    "move_mount_panic": [
        {"name": "unshare", "args": ["unshare_flags_ns"]},
        {"name": "mount", "args": ["addr", "addr", "addr", "mount_flags_move", "addr"]},
    ],
    "seccomp_ptrace_dos": [
        {"name": "seccomp", "args": ["seccomp_flags", "flags", "addr"]},
        {"name": "ptrace", "args": ["ptrace_req_cve", "size", "addr", "addr"]},
    ],
    "socket_fuzz": [
        # This sequence doesn't require a stateful file descriptor,
        # but represents a logical flow: create a socket, then configure it.
        {"name": "socket", "args": ["socket_domain", "socket_type", "flags"]},
        {"name": "setsockopt", "args": ["fd", "flags", "flags", "addr", "size"]},
    ]
}

