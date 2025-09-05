#!/usr/bin/env python3
"""
fuzzer_brain.py - Finalized version

Controls a QEMU Alpine VM, transfers & compiles executor.c inside the VM,
generates syscall calls from fuzzer_config, runs them via SSH, and logs crashes.

Usage:
  - Ensure qemu, sshpass, gcc are available on host and openssh was installed in the VM.
  - Configure VM_* constants below if needed.
  - Run: python3 fuzzer_brain.py
"""

import subprocess
import time
import os
import random
from datetime import datetime
import json
import signal

# Import configuration and generators
from fuzzer_config import SYSCALL_SPECS, SYSCALL_SEQUENCES, TYPE_GENERATORS

# -----------------------
# Config (adjust if necessary)
# -----------------------
VM_DISK_IMAGE = "../alpine.qcow2"
VM_RAM = "1G"
HOST_SSH_PORT = "10022"        # host port forwarded to VM's 22
VM_USER = "root"
VM_PASSWORD = "123"           # set to the password you chose during setup
EXECUTOR_SOURCE_PATH = "executor.c"
EXECUTOR_VM_PATH = "/root/executor"
CRASHES_DIR = "crashes"

# QEMU command (user-mode net with hostfwd for SSH)
QEMU_COMMAND = [
    "qemu-system-x86_64", "-m", VM_RAM, "-hda", VM_DISK_IMAGE, "-nographic",
    "-netdev", f"user,id=net0,hostfwd=tcp::{HOST_SSH_PORT}-:22",
    "-device", "e1000,netdev=net0", "-enable-kvm"
]

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
            time.sleep(3)
            # Try a simple echo command
            retry_timeout = 30
            retry_start = time.time()
            while time.time() - retry_start < retry_timeout:
                res = run_command_in_vm("echo SSH_OK", suppress_errors=True)
                if res is not None and "SSH_OK" in (res.stdout or ""):
                    print("[+] VM is responsive via SSH.")
                    return vm_process
                time.sleep(2)
            print("[!] VM started but SSH did not respond to commands in time.")
            vm_process.terminate()
            return None
        time.sleep(1)

    print("[!] VM SSH port did not open within timeout.")
    vm_process.terminate()
    return None

# -----------------------
# Crash logging (preserve your prior format)
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

    # Attempt to capture dmesg and serial logs from VM (best-effort)
    try:
        # inside VM: write dmesg to a file
        run_command_in_vm(f"dmesg -T > /root/last_dmesg.txt", suppress_errors=True, timeout=15)
        # attempt to fetch it
        fetch_file_from_vm("/root/last_dmesg.txt", os.path.join(base_path, "last_dmesg.txt"))
    except Exception as e:
        print(f"[!] Failed to capture/pull dmesg: {e}")

    try:
        # If you maintain a serial log inside VM at /root/serial.log, try to fetch it
        fetch_file_from_vm("/root/serial.log", os.path.join(base_path, "serial.log"))
    except Exception:
        pass

    # Save any extra files passed in
    if extra_files:
        for name, content in extra_files.items():
            try:
                with open(os.path.join(base_path, name), "w") as fh:
                    fh.write(content)
            except Exception:
                pass

    print(f"[+] All saved under: {base_path}")

# -----------------------
# Fuzzing logic
# -----------------------
def gen_random_syscall():
    """Pick a syscall and generate args using TYPE_GENERATORS."""
    name = random.choice(list(SYSCALL_SPECS.keys()))
    arg_types = SYSCALL_SPECS[name]
    args = []
    for t in arg_types:
        gen = TYPE_GENERATORS.get(t)
        try:
            val = gen()
        except Exception:
            val = 0
        args.append(str(val))
    return name, args

def run_fuzzing_session(vm_process):
    """Main fuzzing loop that runs until a crash is detected or user stops it."""
    print("\n" + "="*50)
    print(" " * 15 + "STARTING FUZZING SESSION")
    print("="*50)

    iteration = 0
    try:
        while True:
            iteration += 1
            print(f"\n--- Iteration #{iteration} ---")

            # Choose to fuzz a single syscall or a predefined sequence
            if random.random() < 0.5 and SYSCALL_SPECS:
                # Single syscall
                print("[+] Fuzzing a single targeted syscall...")
                syscall_name, args = gen_random_syscall()
                command_to_run = f"{EXECUTOR_VM_PATH} {syscall_name} {' '.join(args)}"
                res = run_command_in_vm(command_to_run)
                if res is None:
                    # crash or VM unresponsive detected
                    log_crash(command_to_run)
                    return False
            elif SYSCALL_SEQUENCES:
                # Sequence of syscalls (template)
                print("[+] Fuzzing a syscall sequence...")
                sequence_name, steps = random.choice(list(SYSCALL_SEQUENCES.items()))
                print(f"   [+] Selected sequence: {sequence_name}")

                full_sequence_commands = []
                for step in steps:
                    name = step["name"]
                    arg_types = step["args"]
                    args = []
                    for t in arg_types:
                        gen = TYPE_GENERATORS.get(t, lambda: 0)
                        try:
                            args.append(str(gen()))
                        except Exception:
                            args.append("0")
                    command_to_run = f"{EXECUTOR_VM_PATH} {name} {' '.join(args)}"
                    full_sequence_commands.append(command_to_run)

                    res = run_command_in_vm(command_to_run)
                    if res is None:
                        # Save the commands that lead to crash
                        log_crash(full_sequence_commands)
                        return False
                print("   [+] Sequence completed successfully.")
            else:
                print("[!] No syscall specs/sequences found. Sleeping briefly.")
            # a small delay to avoid hammering the VM too quickly
            time.sleep(0.1)
    except KeyboardInterrupt:
        print("\n[!] Fuzzing session interrupted by user.")
        return True

# -----------------------
# Main control flow
# -----------------------
def main():
    print("[*] Fuzzer starting. Setting deterministic seed (optional via FUZZ_SEED).")
    seed_env = os.environ.get("FUZZ_SEED")
    if seed_env:
        try:
            seed_val = int(seed_env)
        except Exception:
            seed_val = int(time.time() * 1000) & 0xffffffff
    else:
        seed_val = int(time.time() * 1000) & 0xffffffff
    random.seed(seed_val)
    print(f"[+] Seed: {seed_val}")

    print("[*] Starting VM for setup check...")
    vm_process = start_and_wait_for_vm()
    if vm_process is None:
        print("[!] VM failed to start. Exiting.")
        return

    # Re-transfer and compile executor inside VM to ensure latest
    print("[*] Transferring executor source to VM...")
    if not transfer_file_to_vm(EXECUTOR_SOURCE_PATH, "/root/executor.c"):
        print("[!] Failed to transfer executor source. Halting.")
        vm_process.terminate()
        vm_process.wait()
        return

    print("[*] Installing build tools inside VM (apk add build-base)...")
    if run_command_in_vm("apk add --no-cache build-base", timeout=120) is None:
        print("[!] Failed to install build-base in VM.")
        vm_process.terminate()
        vm_process.wait()
        return

    print("[*] Compiling executor inside VM...")
    if run_command_in_vm(f"gcc /root/executor.c -o {EXECUTOR_VM_PATH}", timeout=60) is None:
        print("[!] Compilation inside VM failed.")
        vm_process.terminate()
        vm_process.wait()
        return

    # Verify compiled executor exists
    if run_command_in_vm(f"test -f {EXECUTOR_VM_PATH}", suppress_errors=True) is None:
        print("[!] Verification of executor failed inside VM.")
        vm_process.terminate()
        vm_process.wait()
        return

    print("[+] Executor compiled and verified in VM. Powering VM down to start fuzz loops.")
    # Shutdown VM and restart per-session to ensure clean state between runs
    run_command_in_vm("poweroff", suppress_errors=True, timeout=10)
    try:
        vm_process.wait(timeout=30)
    except subprocess.TimeoutExpired:
        vm_process.terminate()

    print("\n" + "#"*50)
    print("#" + " "*15 + "FUZZER READY" + " "*21 + "#")
    print("#"*50)

    # Main loop: restart VM per session (gives a clean environment)
    try:
        while True:
            vm_process = start_and_wait_for_vm()
            if vm_process is None:
                print("[!] VM startup failed; halting fuzzing.")
                break

            crashed = not run_fuzzing_session(vm_process)

            print("[*] Session ended. Cleaning up VM...")
            if crashed:
                # If we detected a crash, forcibly terminate and restart for next session
                try:
                    vm_process.terminate()
                    vm_process.wait(timeout=10)
                except Exception:
                    pass
                print("[+] VM terminated after crash. Will restart for next session.")
            else:
                # Graceful shutdown after a clean run
                run_command_in_vm("poweroff", suppress_errors=True, timeout=10)
                try:
                    vm_process.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    vm_process.terminate()
                print("[+] VM shutdown after clean session. Exiting.")
                break

            # brief pause before next session
            time.sleep(3)
    except KeyboardInterrupt:
        print("\n[!] Fuzzer main loop interrupted by user. Shutting down.")
        try:
            vm_process.terminate()
        except Exception:
            pass

if __name__ == "__main__":
    main()
