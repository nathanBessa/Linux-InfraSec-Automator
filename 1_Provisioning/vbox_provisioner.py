#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VirtualBox Infrastructure Provisioner & SSH Hardening Automator.

This script orchestrates the creation, installation, and unattended configuration 
of Linux Mint virtual machines via VirtualBox (VBoxManage). 
It includes the installation of base services (SSH/Apache), generation of secure credentials, 
injection of ED25519 SSH keys, and application of hardening policies.

Author: Nataniel Bessa
Version: 1.1.0
"""

import subprocess
import logging
import time
import os
import secrets
import string
import getpass
from typing import Tuple, List

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

# ==========================================
# Global Settings and Paths
# ==========================================
VBOX_PATH = r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
ISO_PATH = r"C:\Users\your_mint.iso"

if not os.path.exists(VBOX_PATH):
    raise FileNotFoundError(
        f"\n[CRITICAL ERROR] The VBoxManage executable was not found at: {VBOX_PATH}\n"
        "Check the Oracle VirtualBox installation folder."
    )

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('vm_automation_audit.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

# ==========================================
# VirtualBox Interaction Layer
# ==========================================
def execute_vboxmanage(commands: List[str], description: str, ignore_error: bool = False) -> Tuple[bool, str]:
    full_command = [VBOX_PATH] + commands
    logging.info(f"Starting: {description}")
    try:
        result = subprocess.run(full_command, check=True, capture_output=True, text=True)
        logging.info(f"Success: {description}")
        return True, result.stdout.strip()
    except subprocess.CalledProcessError as error:
        if not ignore_error:
            logging.error(f"Failure: {description} - Error: {error.stderr.strip()}")
            print(f"[ERROR] {description}")
        return False, error.stderr.strip()

def execute_guest_command(vm_name: str, user: str, password: str, command: str, use_sudo: bool = False) -> Tuple[bool, str, str]:
    if use_sudo:
        escaped_command = command.replace('"', '\\"')
        final_command = f"echo '{password}' | sudo -S bash -c \"{escaped_command}\""
    else:
        final_command = command

    cmd = [
        "guestcontrol", vm_name, "run", 
        "--exe", "/bin/bash", 
        "--username", user, 
        "--password", password, 
        "--", "-c", final_command
    ]
    full_command = [VBOX_PATH] + cmd
    result = subprocess.run(full_command, capture_output=True, text=True)
    return result.returncode == 0, result.stdout.strip(), result.stderr.strip()

def vm_exists(name: str) -> bool:
    _, output = execute_vboxmanage(["list", "vms"], "Check existing VMs", ignore_error=True)
    return f'"{name}"' in output

def vm_is_running(name: str) -> bool:
    _, output = execute_vboxmanage(["showvminfo", name, "--machinereadable"], "Check VM state", ignore_error=True)
    return 'VMState="running"' in output

# ==========================================
# Security Module (Cryptography and Keys)
# ==========================================
def generate_password(size: int = 24) -> str:
    alphabet = string.ascii_letters + string.digits + string.punctuation
    while True:
        password = ''.join(secrets.choice(alphabet) for _ in range(size))
        if (any(c.islower() for c in password) and any(c.isupper() for c in password) and 
            sum(c.isdigit() for c in password) >= 2 and sum(c in string.punctuation for c in password) >= 2):
            return password

def ssh_gen(target_user: str, vm_name: str) -> bytes:
    print(f"\n[+] Generating secure password and ED25519 key pair for {target_user} on {vm_name}...")
    password = generate_password()
    
    password_file_name = "key_password.txt"
    with open(password_file_name, "a", encoding="utf-8") as f:
        f.write(f"SSH Key Password for key ({vm_name} - {target_user}): {password}\n")
    
    private_key = ed25519.Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode('utf-8'))
    )

    private_file_name = f"private_key_{vm_name}_{target_user}.pem"

    with open(private_file_name, "wb") as f:
        f.write(private_bytes)
        
    os.chmod(private_file_name, 0o600)
    print(f"[INFO] Private key saved locally as: {private_file_name}")
    
    public_key = private_key.public_key()
    return public_key.public_bytes(encoding=serialization.Encoding.OpenSSH, format=serialization.PublicFormat.OpenSSH)

# ==========================================
# Main Orchestration Flow
# ==========================================
def main():
    logging.info("--- START OF VIRTUALBOX AUTOMATION ---")

    print("\n" + "="*50)
    print(" INFRASTRUCTURE ORCHESTRATOR - LINUX MINT")
    print("="*50)
    print("1 - Provision VM from scratch (Hardware, OS, and Configuration)")
    print("2 - Configure existing VM (Users, SSH, and Web Base)")
    option = input("Select the directive (1 or 2): ").strip()

    VM_NAME = ""
    GUEST_USER = ""
    GUEST_PASS = ""

    # ==========================================
    # OPTION 1: PROVISIONING AND DISCOVERY
    # ==========================================
    if option == '1':
        VM_NAME = "LinuxMint_WebServer"
        # Base user created by automatic installation for initial administration
        GUEST_USER = "masterofwizards"
        GUEST_PASS = "1q2w3e4r"

        if vm_exists(VM_NAME):
            print(f"\n[ERROR] Naming Conflict: The VM '{VM_NAME}' already exists in the topology. Aborting.")
            exit(1)

        print(f"\n[INFO] Initializing provisioning of machine '{VM_NAME}'...")
        
        execute_vboxmanage(["createvm", "--name", VM_NAME, "--ostype", "Ubuntu_64", "--register"], "VM Registration")
        execute_vboxmanage(["modifyvm", VM_NAME, "--memory", "4096", "--cpus", "4", "--vram", "128"], "CPU/RAM Allocation")
        
        disk_path = f"./{VM_NAME}_disk.vdi"
        execute_vboxmanage(["createmedium", "disk", "--filename", disk_path, "--size", "51200", "--format", "VDI"], "VDI Creation (50GB)")
        execute_vboxmanage(["storagectl", VM_NAME, "--name", "SATA", "--add", "sata", "--controller", "IntelAhci"], "SATA Controller")
        execute_vboxmanage(["storageattach", VM_NAME, "--storagectl", "SATA", "--port", "0", "--device", "0", "--type", "hdd", "--medium", disk_path], "Disk Mount")
        
        execute_vboxmanage(["storagectl", VM_NAME, "--name", "IDE", "--add", "ide"], "IDE Controller")
        execute_vboxmanage(["storageattach", VM_NAME, "--storagectl", "IDE", "--port", "0", "--device", "0", "--type", "dvddrive", "--medium", ISO_PATH], "ISO Mount")
        
        execute_vboxmanage(["modifyvm", VM_NAME, "--nic1", "bridged", "--bridgeadapter1", "MediaTek Wi-Fi 7 MT7925 Wireless LAN Card"], "Network Interface (Bridged)")
        
        unattended_command = [
            "unattended", "install", VM_NAME, "--iso", ISO_PATH, "--user", GUEST_USER,
            "--password", GUEST_PASS, "--country", "PT", "--time-zone", "UTC",
            "--language", "pt_PT", "--install-additions"
        ]
        execute_vboxmanage(unattended_command, "Unattended Configuration Injection (Preseed)")
        execute_vboxmanage(["startvm", VM_NAME, "--type", "gui"], "Booting Installation Process")
        
        print("\n>>> The hypervisor started the VM. The installation proceeds in the background.")
        while True:
            response = input("Has the OS finished bootstrapping and reached the desktop? (y/n): ").strip().lower()
            if response == 'y':
                print("[INFO] Handshake confirmed. Proceeding to post-installation configuration...")
                break
            elif response == 'n':
                print("Waiting for synchronization... (check the VirtualBox console)")
                time.sleep(15)
            else:
                print("Invalid input. Use 'y' to proceed or 'n' to wait.")

        print("\n[INFO] Evaluating current system baseline (Access Control and Services)...")

        # Regional Settings and Base Update
        execute_guest_command(VM_NAME, GUEST_USER, GUEST_PASS, "localectl set-x11-keymap us", use_sudo=True)
        execute_guest_command(VM_NAME, GUEST_USER, GUEST_PASS, "localectl set-locale LANG=pt_PT.UTF-8", use_sudo=True)
        execute_guest_command(VM_NAME, GUEST_USER, GUEST_PASS, "export DEBIAN_FRONTEND=noninteractive && apt-get update && apt-get upgrade -y", use_sudo=True)

        # 1. SSH Installation and Validation
        print("\n[INFO] Checking for the presence of the OpenSSH Server service...")
        is_ssh_installed, _, _ = execute_guest_command(VM_NAME, GUEST_USER, GUEST_PASS, "dpkg -l | grep -w openssh-server")
        if not is_ssh_installed:
            print("[INFO] OpenSSH Server is not installed. Proceeding with installation...")
            execute_guest_command(VM_NAME, GUEST_USER, GUEST_PASS, "export DEBIAN_FRONTEND=noninteractive && apt-get install openssh-server -y", use_sudo=True)
        
        is_ssh_active, _, _ = execute_guest_command(VM_NAME, GUEST_USER, GUEST_PASS, "systemctl is-active ssh")
        if not is_ssh_active:
            print("[INFO] Activating the SSH service...")
            execute_guest_command(VM_NAME, GUEST_USER, GUEST_PASS, "systemctl enable ssh && systemctl start ssh", use_sudo=True)
        else:
            print("[+] OpenSSH Server active and functional.")

        # 2. Dynamic Definition of Target User
        TARGET_USER = input("\nEnter the name of the user to create to manage the machine (SSH/Web access): ").strip()
        
        user_exists, _, _ = execute_guest_command(VM_NAME, GUEST_USER, GUEST_PASS, f"id -u {TARGET_USER}")
        if not user_exists:
            print(f"[INFO] Creating user '{TARGET_USER}'...")
            execute_guest_command(VM_NAME, GUEST_USER, GUEST_PASS, f"useradd -m -s /bin/bash {TARGET_USER}", use_sudo=True)
        
        execute_guest_command(VM_NAME, GUEST_USER, GUEST_PASS, "groupadd -f xpto", use_sudo=True)
        execute_guest_command(VM_NAME, GUEST_USER, GUEST_PASS, f"usermod -aG xpto {TARGET_USER}", use_sudo=True)

        # 3. Additional Packages
        execute_guest_command(VM_NAME, GUEST_USER, GUEST_PASS, "export DEBIAN_FRONTEND=noninteractive && apt-get install pingus apache2 unzip -y", use_sudo=True)

        # 4. SSH Key Implementation
        print("\n[INFO] Orchestrating packages and reinforcing system security (Hardening)...")
        public_bytes_raw = ssh_gen(TARGET_USER, VM_NAME)
        public_key_str = public_bytes_raw.decode('utf-8').strip()

        print("[INFO] Transferring cryptographic material via copyto (VBoxManage)...")
        temp_pub_file = os.path.abspath("temp_key.pub")
        with open(temp_pub_file, "w", encoding="utf-8") as f:
            f.write(public_key_str + "\n")

        cmd_copy = [
            "guestcontrol", VM_NAME, "copyto", temp_pub_file, 
            "--target-directory", "/tmp/authorized_keys", 
            "--username", GUEST_USER, "--password", GUEST_PASS
        ]
        execute_vboxmanage(cmd_copy, "Secure Public Key Transfer")

        execute_guest_command(VM_NAME, GUEST_USER, GUEST_PASS, f"mkdir -p /home/{TARGET_USER}/.ssh", use_sudo=True)
        execute_guest_command(VM_NAME, GUEST_USER, GUEST_PASS, f"mv /tmp/authorized_keys /home/{TARGET_USER}/.ssh/authorized_keys", use_sudo=True)
        execute_guest_command(VM_NAME, GUEST_USER, GUEST_PASS, f"chown -R {TARGET_USER}:{TARGET_USER} /home/{TARGET_USER}/.ssh", use_sudo=True)
        execute_guest_command(VM_NAME, GUEST_USER, GUEST_PASS, f"chmod 700 /home/{TARGET_USER}/.ssh && chmod 600 /home/{TARGET_USER}/.ssh/authorized_keys", use_sudo=True)

        if os.path.exists(temp_pub_file):
            os.remove(temp_pub_file)

        # 5. SSH Hardening
        execute_guest_command(VM_NAME, GUEST_USER, GUEST_PASS, "sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config", use_sudo=True)
        execute_guest_command(VM_NAME, GUEST_USER, GUEST_PASS, "sed -i 's/^#*PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config", use_sudo=True)
        execute_guest_command(VM_NAME, GUEST_USER, GUEST_PASS, "systemctl restart ssh", use_sudo=True)

        # 6. Base Web Preparation
        execute_guest_command(VM_NAME, GUEST_USER, GUEST_PASS, "chown -R root:xpto /var/www/html && chmod -R 775 /var/www/html", use_sudo=True)
        execute_guest_command(VM_NAME, GUEST_USER, GUEST_PASS, "wget -O /tmp/template.zip https://www.w3schools.com/w3css/w3css_templates.zip && unzip -o /tmp/template.zip -d /var/www/html/", use_sudo=True)
        execute_guest_command(VM_NAME, GUEST_USER, GUEST_PASS, f"ln -sfn /var/www/html /home/{TARGET_USER}/website", use_sudo=True)

        logging.info("--- END OF ORCHESTRATION ---")
        print(f"\n[OK] Provisioning and Hardening successfully completed for target account: '{TARGET_USER}'.")


    # ==========================================
    # OPTION 2: CONFIGURATION OF EXISTING VM
    # ==========================================
    elif option == '2':
        VM_NAME = input("\nExact VM identifier in VirtualBox: ").strip()
        
        if not vm_exists(VM_NAME):
            print(f"[ERROR] VM '{VM_NAME}' not found in the hypervisor inventory.")
            exit(1)
            
        GUEST_USER = input("Login Account (Sudoer): ").strip()
        GUEST_PASS = getpass.getpass("Root/Sudo Password (hidden): ").strip()
        
        if not vm_is_running(VM_NAME):
            print(f"[INFO] VM '{VM_NAME}' is suspended/powered off. Sending wake signal...")
            execute_vboxmanage(["startvm", VM_NAME, "--type", "gui"], "VM Power-On")
            print(">>> Waiting 40 seconds for Kernel and network services to stabilize...")
            time.sleep(40)
        else:
            print(f"[INFO] VM '{VM_NAME}' is active. Proceeding with state audit.")

        # 1. Obtaining and Selecting Users
        print("\n[INFO] Searching for available users on the system...")
        _, output_users, _ = execute_guest_command(
            VM_NAME, GUEST_USER, GUEST_PASS, 
            "awk -F: '$3 >= 1000 && $1 != \"nobody\" {print $1}' /etc/passwd"
        )
        
        users = output_users.split('\n') if output_users else []
        print("\n--- Available Users ---")
        for idx, usr in enumerate(users, 1):
            print(f"{idx} - {usr}")
        print(f"{len(users) + 1} - Create NEW user")
        
        choice = input("\nSelect the desired option number: ").strip()
        
        try:
            choice_idx = int(choice)
            if 1 <= choice_idx <= len(users):
                TARGET_USER = users[choice_idx - 1]
                print(f"[+] Selected user: {TARGET_USER}")
            elif choice_idx == len(users) + 1:
                TARGET_USER = input("Enter the name of the new user: ").strip()
                new_pass = getpass.getpass(f"Enter the password for '{TARGET_USER}': ").strip()
                
                print(f"[INFO] Creating user '{TARGET_USER}'...")
                execute_guest_command(VM_NAME, GUEST_USER, GUEST_PASS, f"useradd -m -s /bin/bash {TARGET_USER}", use_sudo=True)
                execute_guest_command(VM_NAME, GUEST_USER, GUEST_PASS, f"echo '{TARGET_USER}:{new_pass}' | chpasswd", use_sudo=True)
                print(f"[+] User '{TARGET_USER}' created successfully.")
            else:
                print("[-] Invalid option. Aborting.")
                exit(1)
        except ValueError:
            print("[-] Invalid input. Aborting.")
            exit(1)

        # 2. SSH Installation and Validation
        print("\n[INFO] Checking the OpenSSH server installation...")
        is_ssh_installed, _, _ = execute_guest_command(VM_NAME, GUEST_USER, GUEST_PASS, "dpkg -l | grep -w openssh-server")
        
        if not is_ssh_installed:
            print("[-] OpenSSH Server is not installed. Installing now...")
            execute_guest_command(VM_NAME, GUEST_USER, GUEST_PASS, "export DEBIAN_FRONTEND=noninteractive && apt-get update && apt-get install openssh-server -y", use_sudo=True)
        
        is_ssh_active, _, _ = execute_guest_command(VM_NAME, GUEST_USER, GUEST_PASS, "systemctl is-active ssh")
        if not is_ssh_active:
            print("[-] The SSH service is not active. Starting...")
            execute_guest_command(VM_NAME, GUEST_USER, GUEST_PASS, "systemctl enable ssh && systemctl start ssh", use_sudo=True)
        else:
            print("[+] OpenSSH Server is installed and active.")

        # 3. SSH Key Management
        print(f"\n[INFO] Checking SSH configuration for '{TARGET_USER}'...")
        has_ssh, _, _ = execute_guest_command(
            VM_NAME, GUEST_USER, GUEST_PASS, 
            f"test -s /home/{TARGET_USER}/.ssh/authorized_keys", use_sudo=True
        )

        if has_ssh:
            print(f"[+] User '{TARGET_USER}' already has an SSH key configured on the server.")
            priv_key = input("Enter the local path to your private key (e.g., private_key_VM_USER.pem): ").strip()
            passphrase = getpass.getpass("Enter the key passphrase (if it exists, otherwise press Enter): ").strip()
            print(f"[INFO] Access data registered for the key: {priv_key}")
        else:
            print(f"[-] User '{TARGET_USER}' does not have an SSH key. Generating and configuring now...")
            
            public_bytes_raw = ssh_gen(TARGET_USER, VM_NAME)
            public_key_str = public_bytes_raw.decode('utf-8').strip()

            temp_pub_file = os.path.abspath(f"temp_key_{TARGET_USER}.pub")
            with open(temp_pub_file, "w", encoding="utf-8") as f:
                f.write(public_key_str + "\n")

            cmd_copy = [
                "guestcontrol", VM_NAME, "copyto", temp_pub_file, 
                "--target-directory", "/tmp/authorized_keys", 
                "--username", GUEST_USER, "--password", GUEST_PASS
            ]
            execute_vboxmanage(cmd_copy, "Secure Public Key Transfer")

            execute_guest_command(VM_NAME, GUEST_USER, GUEST_PASS, f"mkdir -p /home/{TARGET_USER}/.ssh", use_sudo=True)
            execute_guest_command(VM_NAME, GUEST_USER, GUEST_PASS, f"mv /tmp/authorized_keys /home/{TARGET_USER}/.ssh/authorized_keys", use_sudo=True)
            execute_guest_command(VM_NAME, GUEST_USER, GUEST_PASS, f"chown -R {TARGET_USER}:{TARGET_USER} /home/{TARGET_USER}/.ssh", use_sudo=True)
            execute_guest_command(VM_NAME, GUEST_USER, GUEST_PASS, f"chmod 700 /home/{TARGET_USER}/.ssh && chmod 600 /home/{TARGET_USER}/.ssh/authorized_keys", use_sudo=True)

            if os.path.exists(temp_pub_file):
                os.remove(temp_pub_file)
            print("[+] SSH key transferred and configured on the server.")

        # 4. Base Apache Service Validation
        print("\n[INFO] Checking the Apache2 service...")
        is_apache_installed, _, _ = execute_guest_command(VM_NAME, GUEST_USER, GUEST_PASS, "dpkg -l | grep -w apache2")
        
        if not is_apache_installed:
            print("[-] Apache2 is not installed. Installing now...")
            execute_guest_command(VM_NAME, GUEST_USER, GUEST_PASS, "export DEBIAN_FRONTEND=noninteractive && apt-get update && apt-get install apache2 -y", use_sudo=True)
        
        is_apache_active, _, _ = execute_guest_command(VM_NAME, GUEST_USER, GUEST_PASS, "systemctl is-active apache2")
        if not is_apache_active:
            print("[-] Apache2 is not active. Starting the service...")
            execute_guest_command(VM_NAME, GUEST_USER, GUEST_PASS, "systemctl enable apache2 && systemctl start apache2", use_sudo=True)
        else:
            print("[+] Apache2 is installed and active.")
        
        logging.info("--- END OF CONFIGURATION (OPTION 2) ---")
        exit(0)

    else:
        print("[ERROR] Instruction not recognized. Process terminated.")
        exit(1)


if __name__ == "__main__":
    main()
