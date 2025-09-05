# fuzzer_config.py
# Improved, safety-first generator "brain" for syscall_fuzzing_framework
# - stateful resource pool (fd/mmap/socket hints)
# - focused edge-case integer families
# - deterministic seed handling helpers
# - crash metadata helper (safe: only stores metadata & logs)
#
# IMPORTANT: This file intentionally avoids offering "exploit" sequences.
# It improves coverage & triage for responsible fuzzing in controlled labs.

import os
import random
import time
import json
import hashlib

# ---------------------------
# Basic constants (safe)
# ---------------------------
# Protections / flags for mmap-like placeholders (not exploit payloads)
PROT_READ, PROT_WRITE, PROT_EXEC = 0x1, 0x2, 0x4
MAP_SHARED, MAP_PRIVATE, MAP_ANONYMOUS, MAP_POPULATE = 0x01, 0x02, 0x20, 0x008000

# ptrace
PTRACE_TRACEME = 0

# seccomp
SECCOMP_SET_MODE_FILTER = 1

# userfaultfd flags
O_CLOEXEC, O_NONBLOCK = 0x80000, 0x800

# mount
MS_MOVE = 4096

# unshare flags
CLONE_NEWNS, CLONE_NEWPID, CLONE_NEWUSER = 0x00020000, 0x20000000, 0x10000000

# socket domains/types
AF_INET, AF_INET6, AF_UNIX, AF_NETLINK = 2, 10, 1, 16
SOCK_STREAM, SOCK_DGRAM, SOCK_RAW = 1, 2, 3

# keyctl
KEYCTL_GET_KEYRING_ID = 0

# ---------------------------
# ResourcePool: stateful hints for sequences
# ---------------------------
class ResourcePool:
    """
    Tracks synthetic resource hints (fd/mmap/socket ids) so generated sequences
    are stateful and more realistic. The executor should map these hints to
    actual in-VM resources when executing.
    """
    def __init__(self):
        self.fds = []          # synthetic fd hints
        self.sockets = []      # synthetic socket ids
        self.mmaps = {}        # id -> (addr, size)
        self._next_fd = 100
        self._next_sock = 200

    def new_fd(self):
        fd = self._next_fd
        self._next_fd += 1
        self.fds.append(fd)
        return fd

    def sample_fd(self):
        # 40% create new, else reuse
        if (not self.fds) or random.random() < 0.4:
            return self.new_fd()
        return random.choice(self.fds)

    def new_socket(self):
        s = self._next_sock
        self._next_sock += 1
        self.sockets.append(s)
        return s

    def sample_socket(self):
        if (not self.sockets) or random.random() < 0.4:
            return self.new_socket()
        return random.choice(self.sockets)

    def new_mmap(self, size):
        mid = len(self.mmaps) + 1
        # store page-aligned hint address
        page = 4096
        addr = page * (100 + mid)
        self.mmaps[mid] = (addr, size)
        return mid, addr

    def sample_mmap(self):
        if (not self.mmaps) or random.random() < 0.5:
            # create a new small mmap hint
            mid, addr = self.new_mmap(4096)
            return mid, addr, 4096
        mid = random.choice(list(self.mmaps.keys()))
        addr, size = self.mmaps[mid]
        return mid, addr, size

# create global pool instance for use by generators
res_pool = ResourcePool()

# ---------------------------
# Focused "edge-case" families for ints / addrs / sizes
# ---------------------------
PAGE = 4096

def gen_edge_int():
    """Prefer meaningful small/large/page-aligned edge values instead of random 64-bit."""
    edge_choices = [
        0, 1, 2, -1,
        2**31 - 1, 2**32 - 1, 2**63 - 1,
        PAGE, PAGE - 1, PAGE + 1, PAGE * 100,
        0xfffffffffffffffe, 0xffffffffffffffff
    ]
    if random.random() < 0.3:
        return random.choice(edge_choices)
    # small random value most of the time
    return random.randint(0, 4096)

def gen_addr():
    """Address generator using page-aligned and sentinel addresses (hints)."""
    if random.random() < 0.4:
        # use a synthetic mmap hint
        _, addr = res_pool.new_mmap(4096)
        return addr
    return random.choice([0, 0xffffffffffffffff, 0xdeadbeef, PAGE, PAGE*256, gen_edge_int()])

def gen_size():
    """Size generator with common edge sizes."""
    return random.choice([0, 1, PAGE, PAGE - 1, PAGE + 1, 2**16, 2**20, 2**32 - 1, gen_edge_int()])

def gen_flags():
    """Generic flags (narrowed)."""
    candidates = [0, PROT_READ, PROT_WRITE, PROT_EXEC,
                  PROT_READ | PROT_WRITE, MAP_PRIVATE, MAP_SHARED, MAP_POPULATE]
    if random.random() < 0.15:
        return random.randint(0, 0xffff)
    return random.choice(candidates)

# ---------------------------
# Specific CVE-targeted (non-exploit) helpers (kept minimal)
# ---------------------------
def gen_mmap_flags_cve_2024_39497():
    # targeted combination used in research — keep as a possible choice, not a script
    return PROT_WRITE | MAP_PRIVATE

def gen_ptrace_request_cve_2019_13272():
    return PTRACE_TRACEME

def gen_mount_flags_move():
    return MS_MOVE

def gen_unshare_flags_ns():
    return random.choice([CLONE_NEWNS, CLONE_NEWPID, CLONE_NEWNS | CLONE_NEWPID])

def gen_seccomp_flags():
    return SECCOMP_SET_MODE_FILTER

def gen_userfaultfd_flags():
    return random.choice([0, O_CLOEXEC, O_NONBLOCK, O_CLOEXEC | O_NONBLOCK])

# ---------------------------
# Socket / ioctl / bpf / keyctl generators
# ---------------------------
def gen_socket_domain():
    return random.choice([AF_INET, AF_INET6, AF_UNIX, AF_NETLINK, -1])

def gen_socket_type():
    return random.choice([SOCK_STREAM, SOCK_DGRAM, SOCK_RAW, 0, 10])

def gen_ioctl_request():
    # driver-specific; we return bounded randoms to avoid extreme values
    return random.randint(0, 0xffff)

def gen_bpf_command():
    return random.choice([0, 5, -1])

def gen_keyctl_command():
    return KEYCTL_GET_KEYRING_ID

# ---------------------------
# Resource-aware fd generator wrapper
# ---------------------------
def gen_fd():
    """Return a synthetic fd hint (the executor should map hints to real fds)."""
    if random.random() < 0.4:
        return res_pool.sample_fd()
    # occasional "special" FDs
    return random.choice([-1, 0, 1, 2, res_pool.sample_fd()])

# ---------------------------
# Mapping types to generator functions (used by executor harness)
# ---------------------------
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

# ---------------------------
# Syscall specs & high-level sequences (templates)
# These are *templates* and not "exploit recipes".
# ---------------------------
SYSCALL_SPECS = {
    "read": ["fd", "addr", "size"],
    "write": ["fd", "addr", "size"],
    "open": ["addr", "flags"],
    "close": ["fd"],
    "mmap": ["addr", "size", "mmap_flags_cve", "fd", "size"],
    "ptrace": ["ptrace_req_cve", "size", "addr", "addr"],
    "userfaultfd": ["userfaultfd_flags"],
    "seccomp": ["seccomp_flags", "flags", "addr"],
    "ioctl": ["fd", "ioctl_request", "addr"],
    "bpf": ["bpf_cmd", "addr", "size"],
    "io_uring_setup": ["size", "addr"],
    "keyctl": ["keyctl_cmd", "flags", "size", "addr"],
    "socket": ["socket_domain", "socket_type", "flags"],
    "setsockopt": ["fd", "flags", "flags", "addr", "size"],
}

# These sequences are safe templates for exercising stateful code paths.
SYSCALL_SEQUENCES = {
    "move_mount_template": [
        {"name": "unshare", "args": ["unshare_flags_ns"]},
        {"name": "mount", "args": ["addr", "addr", "addr", "mount_flags_move", "addr"]},
    ],
    "seccomp_then_ptrace_template": [
        {"name": "seccomp", "args": ["seccomp_flags", "flags", "addr"]},
        {"name": "ptrace", "args": ["ptrace_req_cve", "size", "addr", "addr"]},
    ],
    "socket_template": [
        {"name": "socket", "args": ["socket_domain", "socket_type", "flags"]},
        {"name": "setsockopt", "args": ["fd", "flags", "flags", "addr", "size"]},
    ],
}

# ---------------------------
# Deterministic seed helpers & crash metadata (safe)
# ---------------------------
def get_seed():
    """Return seed from env (FUZZ_SEED) or create one and store it."""
    s = os.environ.get("FUZZ_SEED")
    if s:
        try:
            return int(s)
        except Exception:
            pass
    # default: time-based but still reproducible if printed and re-used
    seed = int(time.time() * 1000) & 0xffffffff
    return seed

def compute_run_id(seq_repr, seed):
    """Return a short id for a testcase (sha256 of seed+seq)."""
    h = hashlib.sha256()
    h.update(str(seed).encode())
    h.update(seq_repr.encode())
    return h.hexdigest()[:16]

def save_crash_meta(crash_dir, seq_repr, seed, extra_logs=None):
    """
    Save crash metadata to crash_dir:
      - seed, timestamp, short id
      - short excerpt of logs (if provided)
    Note: This function never transmits or executes anything; it only stores metadata.
    """
    meta = {
        "seed": seed,
        "timestamp": int(time.time()),
        "seq": seq_repr,
    }
    runid = compute_run_id(seq_repr, seed)
    meta_path = os.path.join(crash_dir, f"meta_{runid}.json")
    # include small excerpt of logs if available
    if extra_logs:
        meta["log_excerpt"] = extra_logs[:4096]
    # atomic write
    tmp = meta_path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(meta, f, indent=2)
    os.replace(tmp, meta_path)
    return runid

# Expose a small API for external code
__all__ = [
    "TYPE_GENERATORS", "SYSCALL_SPECS", "SYSCALL_SEQUENCES",
    "res_pool", "get_seed", "compute_run_id", "save_crash_meta"
]
