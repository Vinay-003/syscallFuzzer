import subprocess
import time
import os
import random
from datetime import datetime
# Import the new targeted configuration
from fuzzer_config import SYSCALL_SPECS, SYSCALL_SEQUENCES, TYPE_GENERATORS

# --- Configuration ---
VM_DISK_IMAGE = "../alpine.qcow2"
VM_RAM = "1G"
HOST_SSH_PORT = "10022"
VM_USER = "root"
VM_PASSWORD = "123"
EXECUTOR_SOURCE_PATH = "executor.c"
EXECUTOR_VM_PATH = "/root/executor"
CRASHES_DIR = "crashes"

QEMU_COMMAND = [
    "qemu-system-x86_64", "-m", VM_RAM, "-hda", VM_DISK_IMAGE, "-nographic",
    "-netdev", f"user,id=net0,hostfwd=tcp::{HOST_SSH_PORT}-:22",
    "-device", "e1000,netdev=net0", "-enable-kvm"
]

# --- VM Control Functions ---
def check_ssh_ready():
    check_cmd = ["nc", "-z", "localhost", HOST_SSH_PORT]
    try:
        subprocess.run(check_cmd, timeout=2, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
        return False

def run_command_in_vm(command, suppress_errors=False, timeout=20):
    ssh_command = [
        "sshpass", "-p", VM_PASSWORD, "ssh", f"{VM_USER}@localhost",
        "-p", HOST_SSH_PORT, "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=10",
        command
    ]
    try:
        if not suppress_errors: print(f"[*] Running '{command}' in VM...")
        result = subprocess.run(ssh_command, capture_output=True, text=True, timeout=timeout)
        if result.returncode == 0:
            if not suppress_errors:
                print(f"[+] Command successful. Output:\n{result.stdout.strip()}")
            return result
        else:
            if not suppress_errors:
                print(f"[!] Command failed with exit code {result.returncode}.")
                print(f"[!] STDERR:\n{result.stderr}")
            return None
    except subprocess.TimeoutExpired:
        if not suppress_errors: print(f"[!] Error: SSH command for '{command}' timed out after {timeout} seconds.")
        return None
    except Exception as e:
        if not suppress_errors: print(f"[!] An unexpected error occurred: {e}")
        return None

def transfer_file_to_vm(local_path, remote_path):
    print(f"[*] Transferring {local_path} to VM at {remote_path}...")
    scp_command = [
        "sshpass", "-p", VM_PASSWORD, "scp", "-P", HOST_SSH_PORT,
        "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        local_path, f"{VM_USER}@localhost:{remote_path}"
    ]
    try:
        subprocess.run(scp_command, check=True, capture_output=True, text=True, timeout=30)
        print("[+] File transfer successful.")
        return True
    except Exception as e:
        print(f"[!] File transfer failed: {e}")
        if hasattr(e, 'stderr'): print(e.stderr)
        return False

def start_and_wait_for_vm():
    print("[*] Starting VM in the background...")
    vm_process = subprocess.Popen(QEMU_COMMAND)
    print(f"[*] VM process started with PID: {vm_process.pid}")

    print("[*] Waiting for VM to boot and SSH port to open...")
    boot_timeout = 60
    start_time = time.time()
    while time.time() - start_time < boot_timeout:
        if check_ssh_ready():
            print("[+] SSH port is open.")
            time.sleep(3)
            print("[*] Verifying SSH service readiness...")
            retry_timeout = 30
            retry_start_time = time.time()
            while time.time() - retry_start_time < retry_timeout:
                result = run_command_in_vm("echo SSH_OK", suppress_errors=True)
                if result is not None and "SSH_OK" in result.stdout:
                    print("[+] VM is fully responsive.")
                    return vm_process
                time.sleep(3)
            print("[!] VM failed to become responsive to commands.")
            vm_process.terminate()
            return None
    print("[!] VM SSH port did not open in time.")
    vm_process.terminate()
    return None

# --- Fuzzer Logic ---

def log_crash(reproducer_command):
    os.makedirs(CRASHES_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    log_file_path = os.path.join(CRASHES_DIR, f"crash_{timestamp}.log")

    print("\n" + "!"*60)
    print("!!!!!! KERNEL CRASH DETECTED !!!!!!")
    print(f"!!!!!! Saving reproducer to: {log_file_path}")
    print("!"*60)

    with open(log_file_path, "w") as f:
        f.write("--- Syscall Fuzzer Crash Report ---\n")
        f.write(f"Timestamp: {timestamp}\n")
        f.write("\n--- Reproducer Command(s) ---\n")
        f.write(reproducer_command + "\n")

def run_fuzzing_session(vm_process):
    print("\n" + "="*50)
    print(" " * 15 + "STARTING FUZZING SESSION")
    print("="*50)

    iteration = 0
    try:
        while True:
            iteration += 1
            print(f"\n--- Iteration #{iteration} ---")

            # Randomly choose between a single syscall or a sequence
            if random.random() < 0.5 and SYSCALL_SPECS:
                # --- Fuzz a single, targeted syscall ---
                print("[+] Fuzzing a single targeted syscall...")
                syscall_name, arg_types = random.choice(list(SYSCALL_SPECS.items()))
                args = [str(TYPE_GENERATORS.get(t, lambda: 0)()) for t in arg_types]
                command_to_run = f"{EXECUTOR_VM_PATH} {syscall_name} {' '.join(args)}"

                if run_command_in_vm(command_to_run) is None:
                    log_crash(command_to_run)
                    return False # Crash
            elif SYSCALL_SEQUENCES:
                # --- Fuzz a sequence of syscalls ---
                print("[+] Fuzzing a syscall sequence...")
                sequence_name, steps = random.choice(list(SYSCALL_SEQUENCES.items()))
                print(f"   [+] Selected sequence: {sequence_name}")

                full_sequence_command = []
                for step in steps:
                    syscall_name = step["name"]
                    arg_types = step["args"]
                    args = [str(TYPE_GENERATORS.get(t, lambda: 0)()) for t in arg_types]
                    command_to_run = f"{EXECUTOR_VM_PATH} {syscall_name} {' '.join(args)}"
                    full_sequence_command.append(command_to_run)

                    if run_command_in_vm(command_to_run) is None:
                        log_crash("\n".join(full_sequence_command))
                        return False # Crash
                print("   [+] Sequence completed successfully.")
            else:
                print("[!] No syscalls or sequences defined in config. Skipping iteration.")


            time.sleep(0.1)
    except KeyboardInterrupt:
        print("\n[!] Fuzzing session stopped by user.")
        return True # Clean exit

def main():
    print("[*] Starting VM for setup check...")
    vm_process = start_and_wait_for_vm()
    if vm_process is None: return

    # Always re-transfer and re-compile to ensure we have the latest version
    print(f"[!] Executor will be re-compiled to ensure it's up to date.")
    if not transfer_file_to_vm(EXECUTOR_SOURCE_PATH, "/root/executor.c"):
        vm_process.terminate(); return
    if run_command_in_vm("apk add build-base", timeout=120) is None:
        print("[!] FAILED to install compiler."); vm_process.terminate(); return
    if run_command_in_vm(f"gcc /root/executor.c -o {EXECUTOR_VM_PATH}") is None:
        print("[!] FAILED to compile executor."); vm_process.terminate(); return
    if run_command_in_vm(f"test -f {EXECUTOR_VM_PATH}", suppress_errors=True) is None:
        print("[!] VERIFICATION FAILED after compile."); vm_process.terminate(); return
    print("[+] Executor compiled and verified in VM.")

    print("[*] Shutting down VM gracefully after setup check...")
    run_command_in_vm("poweroff", suppress_errors=True, timeout=10)
    try:
        vm_process.wait(timeout=30)
    except subprocess.TimeoutExpired:
        vm_process.terminate()

    print("\n" + "#"*50)
    print("#" + " "*15 + "FUZZER READY" + " "*21 + "#")
    print("#"*50)

    while True:
        vm_process = start_and_wait_for_vm()
        if vm_process is None:
            print("[!] Halting due to VM startup failure.")
            break

        crashed = not run_fuzzing_session(vm_process)

        print("[*] Shutting down fuzzer VM...")
        if crashed:
            vm_process.terminate()
            vm_process.wait()
            print("[+] VM process terminated. Restarting for next session...")
        else:
            run_command_in_vm("poweroff", suppress_errors=True, timeout=10)
            try:
                vm_process.wait(timeout=30); print("[+] VM has shut down.")
            except subprocess.TimeoutExpired:
                vm_process.terminate()
            break

        time.sleep(3)

if __name__ == "__main__":
    main()

# healthcare 