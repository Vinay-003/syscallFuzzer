# Linux Syscall Fuzzer: Full Setup Guide

This guide provides a comprehensive, step-by-step process to set up the environment for this coverage-guided syscall fuzzer. This includes setting up the host machine, creating a virtual machine with Alpine Linux, and compiling a custom Linux kernel with KCOV support.

## Section 1: Host Machine Setup (Prerequisites)

This setup is based on a Debian/Ubuntu Linux distribution.

### 1.1 Install Core Software

First, install QEMU (the virtualizer), build tools, Python, and `sshpass` for automated SSH logins.

```bash
# Update your package list
sudo apt-get update

# Install all necessary tools
sudo apt-get install qemu-system-x86 build-essential python3 sshpass -y
```

-----

## Section 2: VM Image Creation (One-Time Setup)

We will create a virtual machine using a minimal Alpine Linux image.

### 2.1 Download Alpine Linux

Download the "Virtual" x86\_64 ISO from the official Alpine website.

```bash
# This command downloads a known-good version
wget https://dl-cdn.alpinelinux.org/alpine/v3.22.1/releases/x86_64/alpine-virt-3.22.1-x86_64.iso
```

### 2.2 Create a Virtual Disk

Create a 10GB virtual hard drive for the VM.

```bash
qemu-img create -f qcow2 alpine.qcow2 10G
```

### 2.3 Install Alpine Linux

Boot the VM from the ISO to install the operating system.

```bash
qemu-system-x86_64 \
  -m 2G \
  -hda alpine.qcow2 \
  -cdrom alpine-virt-3.22.1-x86_64.iso \
  -boot d
```

Inside the QEMU window, a login prompt will appear. Log in as `root` (no password) and run `setup-alpine`. Follow the prompts with these answers:

  * **Select keyboard layout:** `us`
  * **Select variant:** `us`
  * **Select hostname:** `alpine-fuzzer`
  * **Which one would you like to initialize?:** `eth0` (press Enter)
  * **Ip address for eth0?:** `dhcp` (press Enter)
  * **Do you want to do any manual network configuration?:** `n`
  * **New password:** `123` (and again to confirm)
  * **Which timezone?:** `UTC` (or your preference)
  * **HTTP/FTP proxy URL?:** `none` (press Enter)
  * **Which NTP client to run?:** `chrony` (press Enter)
  * **Enter mirror number:** `1`
  * **Which SSH server?:** `openssh` **\<-- VERY IMPORTANT\!**
  * **Which disk(s) would you like to use?:** `sda` **\<-- VERY IMPORTANT\!**
  * **How would you like to use it?:** `sys` **\<-- VERY IMPORTANT\!**
  * **Erase the above disk(s) and continue?:** `y`

After the installation finishes, type `poweroff`. The VM will shut down.

-----

## Section 3: Custom Kernel Compilation (KCOV Setup)

To enable coverage-guided fuzzing, we must build a custom kernel with KCOV enabled. The following steps will automate this complex process.

### 3.1 Start and Access the VM

Start your newly installed VM. This command forwards port `10022` on your host to port `22` in the VM.

```bash
# In Terminal 1 (leave this running)
qemu-system-x86_64 -m 2G -hda alpine.qcow2 -nographic -netdev user,id=net0,hostfwd=tcp::10022-:22
```

In a **new, separate terminal**, connect to the VM via SSH.

```bash
# In Terminal 2
sshpass -p '123' ssh root@localhost -p 10022
```

### 3.2 Run the All-in-One Compilation Script

Inside the VM's SSH session, paste and run the entire script block below. This script will install all dependencies, download a standard LTS kernel, configure it for KCOV, compile it, and reboot.

⚠️ **Warning:** This process will take a very long time (potentially over an hour).

```bash
# This command ensures that the script will exit immediately if any command fails.
set -e

# --- Step 1: Install Dependencies ---
echo "INFO: Installing necessary tools..."
apk update
apk add build-base ncurses-dev linux-headers bc flex bison openssl-dev elfutils-dev wget grep bash perl

# --- Step 2: Download & Extract Kernel Source ---
echo "INFO: Creating source directory..."
mkdir -p /usr/src
cd /usr/src

echo "INFO: Downloading standard LTS kernel version: 6.6.30"
wget "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.6.30.tar.xz"
tar -xf "linux-6.6.30.tar.xz"
ln -s "linux-6.6.30" linux
cd linux

# --- Step 3: Configure the Kernel for KCOV ---
echo "INFO: Creating a default kernel config for this system..."
make defconfig

echo "INFO: Enabling KCOV, DebugFS, and other required options..."
scripts/config --enable DEBUG_FS
scripts/config --enable KCOV
scripts/config --module VIRTIO_PCI
scripts/config --module VIRTIO_NET
scripts/config --module VIRTIO_BLK
scripts/config --module VIRTIO_CONSOLE

echo "INFO: Preparing final configuration..."
make olddefconfig

# --- Step 4: Build & Install ---
CORE_COUNT=$(nproc)
echo "INFO: Starting kernel build with $CORE_COUNT cores. This will take a while..."
make -j$CORE_COUNT
echo "INFO: Build complete. Installing modules..."
make modules_install
echo "INFO: Modules installed. Installing kernel..."
make install

# --- Step 5: Final Bootloader Update & Reboot ---
echo "INFO: Manually updating bootloader..."
sed -i 's/vmlinuz-virt/vmlinuz/' /boot/extlinux.conf

echo "INFO: Kernel installation complete. The VM will now reboot."
reboot
```

### 3.3 Verify the New Kernel

The script will automatically reboot the VM. After waiting a minute, log in again via SSH and run these two commands to verify success:

```bash
# 1. Check the kernel version
uname -r
# Expected output: 6.6.30

# 2. Check for the KCOV file
ls /sys/kernel/debug/kcov
# Expected output: The command should succeed without a 'No such file or directory' error.
```

-----

## Section 4: Running the Fuzzer

Your environment is now fully prepared. The main Python script will handle starting, setting up, and fuzzing the VM.

### 4.1 Project Structure

Make sure your `alpine.qcow2` file is located one level outside your source directory.

```
osProject/
├── alpine.qcow2
└── src/
    ├── fuzzer_config.py
    ├── fuzzer_brain.py
    └── executor.c
```

### 4.2 Launch the Fuzzer

From your host machine, navigate to the `src` directory and run the main Python script.

```bash
cd /path/to/osProject/src
python3 fuzzer_config.py
```

The fuzzer will start, and you will see output as it discovers new kernel code paths, saving the interesting inputs to the `corpus` directory.

simple_metrics.py is used for testing 
