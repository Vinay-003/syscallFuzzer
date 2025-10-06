#!/usr/bin/env python3
"""
fuzzer_brain.py - Enhanced Finalized Version

Controls a QEMU Alpine VM, transfers & compiles executor.c inside the VM,
generates syscall calls from fuzzer_config, runs them via SSH, and logs crashes.


"""

import subprocess
import time
import os
import random
import re
from datetime import datetime
import json
import signal

# Import configuration and generators
from old.fuzzer_config import SYSCALL_SPECS, SYSCALL_SEQUENCES, TYPE_GENERATORS

# -----------------------
# Config (adjust if necessary)
# -----------------------
VM_DISK_IMAGE = "../alpine.qcow2"
VM_RAM = "1G"
HOST_SSH_PORT = "10022"        # host port forwarded to VM's 22
VM_USER = "root"
VM_PASSWORD = "123"            # set to the password you chose during setup
EXECUTOR_SOURCE_PATH = "executor.c"
EXECUTOR_VM_PATH = "/root/executor"
CRASHES_DIR = "crashes"

# QEMU command (user-mode net with hostfwd for SSH)
QEMU_COMMAND = [
    "qemu-system-x86_64", "-m", VM_RAM, "-hda", VM_DISK_IMAGE, "-nographic",
    "-netdev", f"user,id=net0,hostfwd=tcp::{HOST_SSH_PORT}-:22",
    "-device", "e1000,netdev=net0", "-enable-kvm"
]

# Regex for parsing executor output
RE_SYSCALL_RET = re.compile(r"syscall\((\d+)\)\s*=\s*(-?\d+)")

# -----------------------
# Helper: shell/ssh utilities
# -----------------------
def check_ssh_ready():
    """Return True if host port for SSH is open (nc check)."""
    check_cmd = ["nc", "-z", "localhost", HOST_SSH_PORT]
    try:
        subprocess.run(check_cmd, timeout=2, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
        return False

def run_command_in_vm(command, suppress_errors=False, timeout=20):
    """
    Run a command in the VM via ssh and return subprocess.CompletedProcess on success,
    or None on failure/timeout.
    """
    ssh_command = [
        "sshpass", "-p", VM_PASSWORD, "ssh", f"{VM_USER}@localhost",
        "-p", HOST_SSH_PORT, "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=10",
        command
    ]
    try:
        if not suppress_errors:
            print(f"[*] Running in VM: {command}")
        result = subprocess.run(ssh_command, capture_output=True, text=True, timeout=timeout)
        if result.returncode == 0:
            if not suppress_errors:
                if result.stdout and result.stdout.strip():
                    print(f"[+] Output:\n{result.stdout.strip()}")
            return result
        else:
            if not suppress_errors:
                print(f"[!] Command failed (exit {result.returncode}). STDERR:\n{result.stderr.strip()}")
            return None
    except subprocess.TimeoutExpired:
        if not suppress_errors:
            print(f"[!] SSH command timed out after {timeout}s: {command}")
        return None
    except Exception as e:
        if not suppress_errors:
            print(f"[!] SSH error while running '{command}': {e}")
        return None

def transfer_file_to_vm(local_path, remote_path):
    """Copy a host file into the VM using scp (sshpass wrapper)."""
    print(f"[*] Transferring {local_path} -> VM:{remote_path}")
    scp_command = [
        "sshpass", "-p", VM_PASSWORD, "scp", "-P", HOST_SSH_PORT,
        "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        local_path, f"{VM_USER}@localhost:{remote_path}"
    ]
    try:
        subprocess.run(scp_command, check=True, capture_output=True, text=True, timeout=30)
        print("[+] Transfer OK")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] scp failed (rc={e.returncode}). STDERR:\n{e.stderr}")
        return False
    except Exception as e:
        print(f"[!] scp exception: {e}")
        return False

def fetch_file_from_vm(remote_path, local_path):
    """Copy a file from VM back to host (scp). Returns True on success."""
    print(f"[*] Fetching VM:{remote_path} -> {local_path}")
    scp_command = [
        "sshpass", "-p", VM_PASSWORD, "scp", "-P", HOST_SSH_PORT,
        "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        f"{VM_USER}@localhost:{remote_path}", local_path
    ]
    try:
        subprocess.run(scp_command, check=True, capture_output=True, text=True, timeout=30)
        print("[+] Fetch OK")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] fetch scp failed (rc={e.returncode}). STDERR:\n{e.stderr}")
        return False
    except Exception as e:
        print(f"[!] fetch exception: {e}")
        return False

# -----------------------
# VM startup & readiness
# -----------------------
def start_and_wait_for_vm():
    """Start QEMU and wait until SSH becomes responsive inside VM. Return Popen handle or None."""
    print("[*] Starting VM...")
    vm_process = subprocess.Popen(QEMU_COMMAND, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    print(f"[*] VM PID: {vm_process.pid}. Waiting for SSH port to open...")
    boot_timeout = 60
    start_time = time.time()
    while time.time() - start_time < boot_timeout:
        if check_ssh_ready():
            print("[+] SSH port open; validating in-VM responsiveness...")
            # small wait for SSH service
            time.sleep(10)
            # Try a simple echo command
            retry_timeout = 30
            retry_start = time.time()
            while time.time() - retry_start < retry_timeout:
                res = run_command_in_vm("echo SSH_OK", suppress_errors=True)
                if res is not None and "SSH_OK" in (res.stdout or ""):
                    print("[+] VM is responsive via SSH.")
                    return vm_process
                time.sleep(3)
            print("[!] VM started but SSH did not respond to commands in time.")
            vm_process.terminate()
            return None
        time.sleep(1)

    print("[!] VM SSH port did not open within timeout.")
    vm_process.terminate()
    return None

# -----------------------
# Crash logging
# -----------------------
def log_crash(reproducer_command, extra_files=None):
    """Save a crash report and attempt to fetch dmesg/serial logs from VM."""
    os.makedirs(CRASHES_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    runid = timestamp
    base_path = os.path.join(CRASHES_DIR, f"crash_{runid}")
    os.makedirs(base_path, exist_ok=True)
    log_file_path = os.path.join(base_path, f"crash_{runid}.log")

    print("\n" + "!"*60)
    print("!!!!!! KERNEL CRASH (or interesting failure) DETECTED !!!!!!")
    print(f"!!!!!! Saving reproducer to: {log_file_path}")
    print("!"*60)

    with open(log_file_path, "w") as f:
        f.write("--- Syscall Fuzzer Crash Report ---\n")
        f.write(f"Timestamp: {timestamp}\n")
        f.write("\n--- Reproducer Command(s) ---\n")
        if isinstance(reproducer_command, (list, tuple)):
            f.write("\n".join(reproducer_command) + "\n")
        else:
            f.write(str(reproducer_command) + "\n")

    # Attempt to capture dmesg and serial logs from VM
    try:
        run_command_in_vm(f"dmesg -T > /root/last_dmesg.txt", suppress_errors=True, timeout=15)
        fetch_file_from_vm("/root/last_dmesg.txt", os.path.join(base_path, "last_dmesg.txt"))
    except Exception as e:
        print(f"[!] Failed to capture/pull dmesg: {e}")

    try:
        fetch_file_from_vm("/root/serial.log", os.path.join(base_path, "serial.log"))
    except Exception:
        pass

    if extra_files:
        for name, content in extra_files.items():
            try:
                with open(os.path.join(base_path, name), "w") as fh:
                    fh.write(content)
            except Exception:
                pass

    print(f"[+] All saved under: {base_path}")

# -----------------------
# Parsing + argument resolution
# -----------------------
def parse_executor_output(stdout):
    """Parse executor output for return value (int) if available."""
    if not stdout:
        return None
    m = RE_SYSCALL_RET.search(stdout)
    if m:
        try:
            return int(m.group(2))
        except Exception:
            return None
    return None

def resolve_arg(arg_spec, env):
    """
    Resolve argument spec into a concrete value string.
    - {"value":"fd1"} -> env lookup
    - type string -> generator
    - fallback -> literal string/number
    """
    if isinstance(arg_spec, dict) and "value" in arg_spec:
        return str(env.get(arg_spec["value"], 0))
    if isinstance(arg_spec, str):
        if arg_spec in env:
            return str(env[arg_spec])
        gen = TYPE_GENERATORS.get(arg_spec)
        if gen:
            try:
                return str(gen())
            except Exception:
                return "0"
        return arg_spec
    return str(arg_spec)

# -----------------------
# Fuzzing logic
# -----------------------
def gen_random_syscall():
    """Pick a syscall and generate args using TYPE_GENERATORS."""
    name = random.choice(list(SYSCALL_SPECS.keys()))
    arg_types = SYSCALL_SPECS[name]
    args = [resolve_arg(t, {}) for t in arg_types]
    return name, args

def run_fuzzing_session(vm_process):
    """Main fuzzing loop until crash or stop."""
    print("\n" + "="*50)
    print(" " * 15 + "STARTING FUZZING SESSION")
    print("="*50)

    iteration = 0
    try:
        while True:
            iteration += 1
            print(f"\n--- Iteration #{iteration} ---")

            if random.random() < 0.5 and SYSCALL_SPECS:
                # Single syscall
                syscall_name, args = gen_random_syscall()
                command_to_run = f"{EXECUTOR_VM_PATH} {syscall_name} {' '.join(args)}"
                res = run_command_in_vm(command_to_run)
                if res is None:
                    log_crash(command_to_run)
                    return False
                ret = parse_executor_output(res.stdout)
                print(f"[+] Return value: {ret}")
            elif SYSCALL_SEQUENCES:
                # Sequence with env + placeholders
                sequence_name, steps = random.choice(list(SYSCALL_SEQUENCES.items()))
                print(f"[+] Fuzzing sequence: {sequence_name}")
                env = {}
                full_sequence = []
                for step in steps:
                    name = step.get("action") or step.get("name")
                    args = [resolve_arg(a, env) for a in step.get("args", [])]
                    command_to_run = f"{EXECUTOR_VM_PATH} {name} {' '.join(args)}"
                    full_sequence.append(command_to_run)
                    res = run_command_in_vm(command_to_run)
                    if res is None:
                        log_crash(full_sequence)
                        return False
                    ret = parse_executor_output(res.stdout)
                    if step.get("result"):
                        env[step["result"]] = ret if ret is not None else 0
                        print(f"    [env] {step['result']} = {env[step['result']]}")
                print("   [+] Sequence completed successfully.")
            else:
                print("[!] No syscall specs/sequences found. Sleeping briefly.")
            time.sleep(0.1)
    except KeyboardInterrupt:
        print("\n[!] Fuzzing session interrupted by user.")
        return True

# -----------------------
# Main control flow
# -----------------------
def main():
    print("[*] Fuzzer starting with seed.")
    seed_val = int(time.time() * 1000) & 0xffffffff
    random.seed(seed_val)
    print(f"[+] Seed: {seed_val}")

    vm_process = start_and_wait_for_vm()
    if vm_process is None:
        print("[!] VM failed to start.")
        return

    # Transfer and compile executor inside VM
    if not transfer_file_to_vm(EXECUTOR_SOURCE_PATH, "/root/executor.c"):
        print("[!] Transfer failed.")
        vm_process.terminate()
        return
    run_command_in_vm("apk add --no-cache build-base", timeout=120)
    if run_command_in_vm(f"gcc /root/executor.c -o {EXECUTOR_VM_PATH}", timeout=60) is None:
        print("[!] Compilation failed inside VM.")
        vm_process.terminate()
        return

    if run_command_in_vm(f"test -f {EXECUTOR_VM_PATH}", suppress_errors=True) is None:
        print("[!] Executor missing inside VM.")
        vm_process.terminate()
        return

    print("[+] Executor compiled. Powering off VM for clean session...")
    run_command_in_vm("poweroff", suppress_errors=True, timeout=10)
    try:
        vm_process.wait(timeout=30)
    except subprocess.TimeoutExpired:
        vm_process.terminate()

    print("\n" + "#"*50)
    print("#" + " "*15 + "FUZZER READY" + " "*21 + "#")
    print("#"*50)

    try:
        while True:
            vm_process = start_and_wait_for_vm()
            if vm_process is None:
                print("[!] VM startup failed.")
                break
            crashed = not run_fuzzing_session(vm_process)
            print("[*] Session ended. Cleaning up VM...")
            if crashed:
                vm_process.terminate()
                print("[+] VM terminated after crash. Restarting next session.")
            else:
                run_command_in_vm("poweroff", suppress_errors=True, timeout=10)
                try:
                    vm_process.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    vm_process.terminate()
                print("[+] VM shutdown cleanly. Exiting.")
                break
            time.sleep(3)
    except KeyboardInterrupt:
        print("\n[!] Interrupted. Shutting down VM...")
        try:
            vm_process.terminate()
        except Exception:
            pass

if __name__ == "__main__":
    main()





"""
Enhancements:
 - Parse executor output ("syscall(N) = <ret>") and capture return values.
 - Store results in env when "result" key is present in sequence steps.
 - Resolve {"value":"fd1"} placeholders in args using stored env.
"""