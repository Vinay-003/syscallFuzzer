Step 1: Install Core Software on Your Host Machine

First, we need to install QEMU (the virtualizer), a C compiler, and Python. Open a terminal on your Linux machine (or WSL on Windows) and run the following:

# Update your package list
sudo apt-get update

# Install QEMU, build tools (for GCC compiler), and Python
sudo apt-get install qemu-system-x86 build-essential python3 -y


This single command gets all the necessary tools.
Step 2: Download a Minimal Linux Image

We'll use Alpine Linux because it's tiny and boots in seconds.

    Go to the Alpine Linux downloads page: https://alpinelinux.org/downloads/

    Find the "VIRTUAL" section for the "x86_64" architecture.

    Download the ISO file. You can use wget to do this from your terminal. Find the latest version link on the site and use it like this:

    # Updated for version 3.22.1
    wget [https://dl-cdn.alpinelinux.org/alpine/v3.22.1/releases/x86_64/alpine-virt-3.22.1-x86_64.iso](https://dl-cdn.alpinelinux.org/alpine/v3.22.1/releases/x86_64/alpine-virt-3.22.1-x86_64.iso)

Step 3: Create a Virtual Disk and Install Alpine (One-Time Setup)

This is the only manual part. We need to create a virtual hard drive and install Alpine from the ISO onto it.

    Create a virtual disk image (10GB is plenty):

    qemu-img create -f qcow2 alpine.qcow2 10G

    Boot the installer: Run the following command. This will start a VM and open a QEMU window.

    qemu-system-x86_64 \
      -m 2G \
      -hda alpine.qcow2 \
      -cdrom alpine-virt-3.22.1-x86_64.iso \
      -boot d

    Inside the QEMU window, install Alpine:

        You will see a black screen with a login prompt. Type root and press Enter.

        Run the installer script by typing: setup-alpine

        Follow the prompts. Here are the most important answers:

            Select keyboard layout: us

            Select variant: us (just press Enter to accept the default)

            Select hostname: alpine-fuzzer

            Which one would you like to initialize?: eth0 (just press Enter)

            Ip address for eth0?: dhcp (just press Enter)

            Do you want to do any manual network configuration?: n (just press Enter)

            New password: Set a simple password you will remember (set it to “123").

            Which timezone?: UTC is fine.

            HTTP/FTP proxy URL?: none (just press Enter)

            Which NTP client to run?: chrony (just press Enter)

            Enter mirror number: 1 is fine.

            Which SSH server?: openssh (type openssh and press Enter) <-- VERY IMPORTANT!

            Which disk(s) would you like to use?: sda (type sda and press Enter) <-- VERY IMPORTANT!

            How would you like to use it?: sys (type sys and press Enter) <-- VERY IMPORTANT!

            WARNING... Erase the above disk(s) and continue?: y

        The installation will complete. Type poweroff and press Enter. The QEMU window will close.

Your alpine.qcow2 file now contains a fully installed and ready-to-use Linux system.
Step 4: Automate It!

Now for the final step. The Python script below will manage the VM for you. Save it and run it. It will prove your entire setup works.


AFTER ALL THIS DO THE BELOW STUFF:

sudo apt-get install sshpass

the alpine.qcow2 file u just made should be outside of the src directory 