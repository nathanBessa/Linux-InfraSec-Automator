#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Automated SSL/TLS Provisioning and Apache Configuration Orchestrator.

This script automates the secure configuration of Apache2 web servers via SSH.
It uses the local VirtualBox API (VBoxManage) for Discovery and establishes native 
SSH tunnels with an Administrator account for Deployment (Hardening, SSL, and ACLs),
ultimately delegating strict access to the target user (Role Separation).

Author: Nataniel Bessa
Version: 1.1.1
"""

import os
import paramiko
import logging
import getpass
import subprocess
from typing import Tuple, List

# ==========================================
# Global Settings and Paths
# ==========================================
VBOX_PATH = r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"

if not os.path.exists(VBOX_PATH):
    raise FileNotFoundError(
        f"\n[CRITICAL ERROR] The VBoxManage executable was not found at: {VBOX_PATH}\n"
        "Check the Oracle VirtualBox installation folder."
    )

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ssl_config_audit.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

# ==========================================
# Local Interaction Layer (VirtualBox API)
# ==========================================
def execute_vboxmanage(commands: List[str], description: str, ignore_error: bool = False) -> Tuple[bool, str]:
    full_command = [VBOX_PATH] + commands
    try:
        result = subprocess.run(full_command, check=True, capture_output=True, text=True)
        return True, result.stdout.strip()
    except subprocess.CalledProcessError as error:
        if not ignore_error:
            logging.error(f"Failed to execute VBoxManage: {description} - Error: {error.stderr.strip()}")
        return False, error.stderr.strip()

def execute_guest_command(vm_name: str, user: str, password: str, command: str) -> Tuple[bool, str, str]:
    cmd = [
        "guestcontrol", vm_name, "run", 
        "--exe", "/bin/bash", 
        "--username", user, 
        "--password", password, 
        "--", "-c", command
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
# Remote Execution Layer (SSH / Web)
# ==========================================
def execute_sudo(ssh_client: paramiko.SSHClient, sudo_password: str, command: str) -> Tuple[bool, str, str]:
    escaped_command = command.replace('"', '\\"')
    final_command = f"echo '{sudo_password}' | sudo -S bash -c \"{escaped_command}\""
    
    stdin, stdout, stderr = ssh_client.exec_command(final_command)
    exit_status = stdout.channel.recv_exit_status()
    
    return exit_status == 0, stdout.read().decode().strip(), stderr.read().decode().strip()

def reset_ssl_apache(ssh_client: paramiko.SSHClient, sudo_password: str) -> bool:
    logging.info("    [*] Checking the integrity of the Apache2 installation...")
    _, stdout, _ = ssh_client.exec_command("dpkg -l | grep -w apache2")
    
    if "apache2" not in stdout.read().decode():
        logging.warning("    [!] Apache2 not detected on the target system.")
        response = input("    [?] Do you want to provision Apache2 now? (y/n): ").strip().lower()
        
        if response == 'y':
            logging.info("    [*] Starting Apache2 installation. This process may take a while...")
            install_command = "export DEBIAN_FRONTEND=noninteractive && apt-get update && apt-get install apache2 -y"
            success, _, err = execute_sudo(ssh_client, sudo_password, install_command)
            
            if not success:
                logging.error(f"    [-] Failure provisioning Apache2: {err}")
                return False
            logging.info("    [+] Apache2 provisioned successfully.")
        else:
            logging.error("    [-] Installation cancelled by the user. Aborting SSL orchestration.")
            return False
    else:
        logging.info("    [+] Apache2 service found.")
        
    logging.info("    [*] Purging residual SSL configurations (State Reset)...")
    reset_commands = [
        "a2dismod ssl || true",
        "a2dissite default-ssl || true",
        "a2dissite custom-ssl || true",
        "rm -f /etc/apache2/sites-available/custom-ssl.conf",
        "systemctl reload apache2 || true"
    ]
    
    for cmd in reset_commands:
        execute_sudo(ssh_client, sudo_password, cmd)
        
    logging.info("    [+] Web environment prepared for injection of new certificates.")
    return True

# Parameter modification: added vm_name and target_user
def generate_and_fetch_ssl(ssh_client: paramiko.SSHClient, sudo_password: str, local_dir: str, admin_user: str, host: str, vm_name: str, target_user: str) -> bool:
    logging.info("    [*] Generating key pair and x509 certificate (RSA 2048) with SAN support...")
    
    cert_subj = f"/C=PT/ST=Local/L=Local/O=Administration/CN={host}"
    cmd_ssl = f"openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /tmp/server.key -out /tmp/server.crt -subj '{cert_subj}' -addext 'subjectAltName=IP:{host}'"
    
    success, _, error = execute_sudo(ssh_client, sudo_password, cmd_ssl)
    if not success:
        logging.error(f"    [-] Cryptographic failure generating the certificate: {error}")
        return False
        
    # chown is done for the admin temporarily so SFTP can extract it
    execute_sudo(ssh_client, sudo_password, f"chown {admin_user}:{admin_user} /tmp/server.crt /tmp/server.key")
    
    # Dynamic construction of file names based on VM and User
    local_crt_name = f"certificate_{vm_name}_{target_user}.crt"
    local_key_name = f"key_{vm_name}_{target_user}.key"

    logging.info(f"    [*] Extracting public certificate and private key for local audit ({local_crt_name})...")
    try:
        sftp = ssh_client.open_sftp()
        sftp.get("/tmp/server.crt", os.path.join(local_dir, local_crt_name))
        sftp.get("/tmp/server.key", os.path.join(local_dir, local_key_name))
        sftp.close()
        logging.info(f"    [+] Cryptographic artifacts successfully transferred to: {local_dir}")
    except Exception as e:
        logging.error(f"    [-] Error in the SFTP layer during transfer: {e}")
        return False

    logging.info("    [*] Applying the artifacts to the definitive directories (/etc/ssl/)...")
    execute_sudo(ssh_client, sudo_password, "mv /tmp/server.crt /etc/ssl/certs/apache-selfsigned.crt")
    execute_sudo(ssh_client, sudo_password, "mv /tmp/server.key /etc/ssl/private/apache-selfsigned.key")
    
    execute_sudo(ssh_client, sudo_password, "chown root:root /etc/ssl/private/apache-selfsigned.key /etc/ssl/certs/apache-selfsigned.crt")
    execute_sudo(ssh_client, sudo_password, "chmod 600 /etc/ssl/private/apache-selfsigned.key")
    
    return True

def configure_apache_ssl(ssh_client: paramiko.SSHClient, sudo_password: str, host: str):
    logging.info("    [*] Injecting the VirtualHost configuration block (TLS/SSL)...")
    
    vhost_config = f"""<VirtualHost *:443>
    ServerName {host}
    DocumentRoot /var/www/html
    ErrorLog ${{APACHE_LOG_DIR}}/error.log
    CustomLog ${{APACHE_LOG_DIR}}/access.log combined
    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/apache-selfsigned.crt
    SSLCertificateKeyFile /etc/ssl/private/apache-selfsigned.key
</VirtualHost>"""
    
    vhost_cmd = f"cat << 'EOF' > /tmp/custom-ssl.conf\n{vhost_config}\nEOF"
    execute_sudo(ssh_client, sudo_password, vhost_cmd)
    execute_sudo(ssh_client, sudo_password, "mv /tmp/custom-ssl.conf /etc/apache2/sites-available/custom-ssl.conf")
    
    activation_commands = [
        "a2enmod ssl",
        "a2ensite custom-ssl",
        "systemctl restart apache2"
    ]
    
    for cmd in activation_commands:
        execute_sudo(ssh_client, sudo_password, cmd)
        
    logging.info("    [+] SSL Engine activated. The server is listening for encrypted traffic on port 443.")

def setup_winscp_access(ssh_client: paramiko.SSHClient, sudo_password: str, target_user: str):
    logging.info("    [*] Implementing ACL policies in the web directory and creating management shortcuts...")
    
    # The target user (without sudo) becomes the owner of the web folder
    execute_sudo(ssh_client, sudo_password, f"chown -R {target_user}:www-data /var/www/html")
    execute_sudo(ssh_client, sudo_password, "chmod -R 750 /var/www/html")
    
    symlink_path = f"/home/{target_user}/Website_Management"
    execute_sudo(ssh_client, sudo_password, f"ln -sfn /var/www/html {symlink_path}")
    execute_sudo(ssh_client, sudo_password, f"chown -h {target_user}:{target_user} {symlink_path}")
    
    logging.info(f"    [+] Secure workspace successfully configured for '{target_user}' at: {symlink_path}")

# ==========================================
# Main Execution Flow
# ==========================================
def main():
    logging.info("[*] Starting Secure Infrastructure Orchestration (Linux Mint)...")

    logging.info("="*60)
    logging.info(" SSL/TLS ENVIRONMENT ORCHESTRATOR")
    logging.info("="*60)
    
    vm_name = input("Enter the target VM name in VirtualBox: ").strip()
    
    if not vm_exists(vm_name):
        logging.error(f"[-] VM '{vm_name}' was not found in the hypervisor.")
        return
        
    if not vm_is_running(vm_name):
        logging.error(f"[-] VM '{vm_name}' is powered off. Please start it first.")
        return

    # 1. Administrator Credentials (Will be used for GuestControl and SSH)
    logging.info(f"    [*] Provide the ADMINISTRATOR credentials for VM '{vm_name}' for orchestration.")
    admin_user = input("Administrator Account (Sudoer): ").strip()
    admin_pass = getpass.getpass("Administrator Password (OS/Sudo - hidden): ").strip()
    
    has_admin_key = input("Does the Administrator authenticate to SSH via key? (y/n): ").strip().lower()
    admin_key_path = None
    admin_ssh_passphrase = None

    if has_admin_key == 'y':
        admin_key_path = input("Path to the SSH Private Key (.pem): ").strip()
        admin_ssh_passphrase = getpass.getpass("SSH Key Passphrase (hidden): ").strip()

    # 2. IP Address Discovery
    logging.info("    [*] Extracting IP address via VirtualBox Guest Additions...")
    success_ip, output_ip, err_ip = execute_guest_command(vm_name, admin_user, admin_pass, "hostname -I | awk '{print $1}'")
    
    if not success_ip or not output_ip:
        logging.error(f"    [-] Failed to obtain IP. Check credentials or Guest Additions. Error: {err_ip}")
        return
        
    host_ip = output_ip.strip()
    logging.info(f"    [+] Operational IP Address Detected: {host_ip}")

    # 3. User Enumeration
    logging.info("    [*] Enumerating valid identities on the system...")
    success_users, output_users, _ = execute_guest_command(
        vm_name, admin_user, admin_pass, 
        "awk -F: '$3 >= 1000 && $1 != \"nobody\" {print $1}' /etc/passwd"
    )
    
    if not success_users or not output_users:
        logging.error("    [-] No valid users detected or access denied.")
        return

    users = [u.strip() for u in output_users.split('\n') if u.strip()]

    # 4. Target User Selection (Role Separation)
    logging.info("--- Available Users ---")
    for idx, usr in enumerate(users, 1):
        logging.info(f"{idx} - {usr}")
        
    try:
        choice = int(input("\nSelect the number of the TARGET user who will manage the site: ").strip())
        if 1 <= choice <= len(users):
            target_user = users[choice - 1]
            logging.info(f"    [+] Target user selected: {target_user}")
        else:
            logging.error("[-] Invalid option. Aborting.")
            return
    except ValueError:
        logging.error("[-] Invalid input. Aborting.")
        return

    logging.info("="*60)

    # 5. SSH Handshake (As Administrator)
    local_dir = os.getcwd() 
    logging.info(f"    [>] Initializing SSH handshake to {host_ip} with the ADMINISTRATOR account ({admin_user})...")
    
    admin_client = paramiko.SSHClient()
    admin_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        if has_admin_key == 'y':
            if not os.path.exists(admin_key_path):
                logging.error(f"\n[CRITICAL ERROR] The key was not found at the specified path: {admin_key_path}")
                return
            admin_client.connect(
                hostname=host_ip, 
                username=admin_user, 
                key_filename=admin_key_path,
                passphrase=admin_ssh_passphrase, 
                timeout=15
            )
        else:
            admin_client.connect(
                hostname=host_ip, 
                username=admin_user, 
                password=admin_pass, 
                timeout=15
            )
            
        logging.info("    [+] SSH Handshake successfully completed.")
        
        # Core Pipeline (Delegating to target_user at the end)
        if not reset_ssl_apache(admin_client, admin_pass):
            return

        # Call to the updated function with vm_name and target_user injection
        if not generate_and_fetch_ssl(admin_client, admin_pass, local_dir, admin_user, host_ip, vm_name, target_user):
            return
            
        configure_apache_ssl(admin_client, admin_pass, host_ip)
        setup_winscp_access(admin_client, admin_pass, target_user)
        
    except paramiko.ssh_exception.PasswordRequiredException:
        logging.error("    [-] Access Denied: The provided passphrase cannot decrypt the private key.")
    except paramiko.AuthenticationException:
        logging.error("    [-] Access Denied: Administrator SSH authentication failed.")
    except Exception as e:
        logging.error(f"    [-] Critical Failure in SSH socket connection: {e}")
    finally:
        admin_client.close()
        logging.info(f"\n{'-'*60}\n[*] Orchestration Pipeline finished. TCP session closed.")

if __name__ == "__main__":
    main()
