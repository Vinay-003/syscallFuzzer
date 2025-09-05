import random

# This file contains the "brain" of the fuzzer.
# This version has been updated to apply the chaotic "random_int" generator
# to almost all syscall arguments to maximize randomness and bug discovery potential.

# --- Constants for Syscall Arguments ---
PROT_READ, PROT_WRITE = 0x1, 0x2
MAP_PRIVATE = 0x02
PTRACE_TRACEME = 0
MS_MOVE = 4096
CLONE_NEWNS, CLONE_NEWPID = 0x00020000, 0x20000000
AF_INET, AF_INET6 = 2, 10
SOCK_STREAM, SOCK_DGRAM, SOCK_RAW = 1, 2, 3

# --- Argument Generators ---

def gen_fd():
    """Generates a smart, interesting file descriptor."""
    return random.choice([-1, 0, 1, 2, 100])

def gen_addr():
    """Generates a smart, interesting memory address."""
    return random.choice([0, 0xffffffffffffffff, 0xdeadbeef, 4096])

def gen_size():
    """Generates a smart, interesting size or length."""
    return random.choice([0, 4096, 2**32-1, -1])

def gen_random_int():
    """Generates a completely random 64-bit integer."""
    return random.randint(-2**63, 2**63 - 1)

# --- CVE and Research-Specific Generators (used sparingly now) ---
def gen_mmap_flags_cve_2024_39497():
    print("   [+] Generating targeted flags for CVE-2024-39497 (mmap)...")
    return PROT_WRITE | MAP_PRIVATE

def gen_ptrace_request_cve_2019_13272():
    print("   [+] Generating targeted request for CVE-2019-13272 (ptrace)...")
    return PTRACE_TRACEME

def gen_mount_flags_move():
    return MS_MOVE

def gen_unshare_flags_ns():
    return random.choice([CLONE_NEWNS, CLONE_NEWPID])

def gen_socket_domain():
    return random.choice([AF_INET, AF_INET6, -1])

def gen_socket_type():
    return random.choice([SOCK_STREAM, SOCK_DGRAM, SOCK_RAW, 10])


# Mapping of type names to their generator functions
TYPE_GENERATORS = {
    # Keep smart generators available if needed
    "fd": gen_fd,
    "addr": gen_addr,
    "size": gen_size,
    "mmap_flags_cve": gen_mmap_flags_cve_2024_39497,
    "ptrace_req_cve": gen_ptrace_request_cve_2019_13272,
    "mount_flags_move": gen_mount_flags_move,
    "unshare_flags_ns": gen_unshare_flags_ns,
    "socket_domain": gen_socket_domain,
    "socket_type": gen_socket_type,
    # The primary generator for most fuzzing now
    "random_int": gen_random_int,
}

# --- Syscall & Sequence Definitions (Chaotic Approach) ---

SYSCALL_SPECS = {
    # *** CHANGE: Apply "random_int" to nearly every argument for maximum chaos ***
    "read": ["random_int", "random_int", "random_int"],
    "write": ["random_int", "random_int", "random_int"],
    "open": ["random_int", "random_int"],
    "close": ["random_int"],
    "userfaultfd": ["random_int"],
    "seccomp": ["random_int", "random_int", "random_int"],
    "ioctl": ["random_int", "random_int", "random_int"],
    "bpf": ["random_int", "random_int", "random_int"],
    "io_uring_setup": ["random_int", "random_int"],
    "keyctl": ["random_int", "random_int", "random_int", "random_int"],
    
    # Keep the highly specific CVE trigger, but randomize the other arguments
    "mmap": ["random_int", "random_int", "mmap_flags_cve", "random_int", "random_int"],
    "ptrace": ["ptrace_req_cve", "random_int", "random_int", "random_int"],
}

SYSCALL_SEQUENCES = {
    "move_mount_panic": [
        {"name": "unshare", "args": ["unshare_flags_ns"]},
        {"name": "mount", "args": ["random_int", "random_int", "random_int", "mount_flags_move", "random_int"]},
    ],
    "socket_fuzz": [
        {"name": "socket", "args": ["socket_domain", "socket_type", "random_int"]},
        {"name": "setsockopt", "args": ["random_int", "random_int", "random_int", "random_int", "random_int"]},
    ]
}

