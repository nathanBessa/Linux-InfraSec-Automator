#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VirtualBox Infrastructure Provisioner & SSH Hardening Automator.

Este script orquestra a criação, instalação e configuração unattended 
de máquinas virtuais Linux Mint via VirtualBox (VBoxManage). 
Inclui a instalação de serviços base (SSH/Apache), geração de credenciais seguras, 
injeção de chaves SSH ED25519, e aplicação de políticas de hardening.

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
# Configurações Globais e Paths
# ==========================================
VBOX_PATH = r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
ISO_PATH = r"C:\Users\Nataniel Bessa\Downloads\ISO\linuxmint-22.3-cinnamon-64bit.iso"

if not os.path.exists(VBOX_PATH):
    raise FileNotFoundError(
        f"\n[ERRO CRÍTICO] O executável VBoxManage não foi encontrado em: {VBOX_PATH}\n"
        "Verifique a pasta de instalação do Oracle VirtualBox."
    )

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('automacao_vm_audit.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

# ==========================================
# Camada de Interação com VirtualBox
# ==========================================
def executar_vboxmanage(comandos: List[str], descricao: str, ignorar_erro: bool = False) -> Tuple[bool, str]:
    comando_completo = [VBOX_PATH] + comandos
    logging.info(f"A iniciar: {descricao}")
    try:
        resultado = subprocess.run(comando_completo, check=True, capture_output=True, text=True)
        logging.info(f"Sucesso: {descricao}")
        return True, resultado.stdout.strip()
    except subprocess.CalledProcessError as erro:
        if not ignorar_erro:
            logging.error(f"Falha: {descricao} - Erro: {erro.stderr.strip()}")
            print(f"[ERRO] {descricao}")
        return False, erro.stderr.strip()

def executar_comando_guest(vm_nome: str, user: str, password: str, comando: str, usar_sudo: bool = False) -> Tuple[bool, str, str]:
    if usar_sudo:
        comando_escapado = comando.replace('"', '\\"')
        comando_final = f"echo '{password}' | sudo -S bash -c \"{comando_escapado}\""
    else:
        comando_final = comando

    cmd = [
        "guestcontrol", vm_nome, "run", 
        "--exe", "/bin/bash", 
        "--username", user, 
        "--password", password, 
        "--", "-c", comando_final
    ]
    comando_completo = [VBOX_PATH] + cmd
    resultado = subprocess.run(comando_completo, capture_output=True, text=True)
    return resultado.returncode == 0, resultado.stdout.strip(), resultado.stderr.strip()

def vm_existe(nome: str) -> bool:
    _, output = executar_vboxmanage(["list", "vms"], "Verificar VMs existentes", ignorar_erro=True)
    return f'"{nome}"' in output

def vm_em_execucao(nome: str) -> bool:
    _, output = executar_vboxmanage(["showvminfo", nome, "--machinereadable"], "Verificar estado da VM", ignorar_erro=True)
    return 'VMState="running"' in output

# ==========================================
# Módulo de Segurança (Criptografia e Chaves)
# ==========================================
def generate_password(size: int = 24) -> str:
    alphabet = string.ascii_letters + string.digits + string.punctuation
    while True:
        password = ''.join(secrets.choice(alphabet) for _ in range(size))
        if (any(c.islower() for c in password) and any(c.isupper() for c in password) and 
            sum(c.isdigit() for c in password) >= 2 and sum(c in string.punctuation for c in password) >= 2):
            return password

def ssh_gen(target_user: str, vm_name: str) -> bytes:
    print(f"\n[+] A gerar password segura e par de chaves ED25519 para {target_user} em {vm_name}...")
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
    print(f"[INFO] Chave privada guardada localmente como: {private_file_name}")
    
    public_key = private_key.public_key()
    return public_key.public_bytes(encoding=serialization.Encoding.OpenSSH, format=serialization.PublicFormat.OpenSSH)

# ==========================================
# Fluxo Principal de Orquestração
# ==========================================
def main():
    logging.info("--- INÍCIO DA AUTOMAÇÃO VIRTUALBOX ---")

    print("\n" + "="*50)
    print(" ORQUESTRADOR INFRAESTRUTURA - LINUX MINT")
    print("="*50)
    print("1 - Provisionar VM do zero (Hardware, SO e Configuração)")
    print("2 - Configurar VM existente (Utilizadores, SSH e Base Web)")
    opcao = input("Selecione a diretiva (1 ou 2): ").strip()

    VM_NAME = ""
    GUEST_USER = ""
    GUEST_PASS = ""

    # ==========================================
    # OPÇÃO 1: PROVISIONAMENTO E DISCOVERY
    # ==========================================
    if opcao == '1':
        VM_NAME = "LinuxMint_WebServer"
        # Utilizador base criado pela instalação automática para administração inicial
        GUEST_USER = "mestredosmagos"
        GUEST_PASS = "1q2w3e4r"

        if vm_existe(VM_NAME):
            print(f"\n[ERRO] Conflito de Nomenclatura: A VM '{VM_NAME}' já existe na topologia. Abortando.")
            exit(1)

        print(f"\n[INFO] A inicializar provisionamento da máquina '{VM_NAME}'...")
        
        executar_vboxmanage(["createvm", "--name", VM_NAME, "--ostype", "Ubuntu_64", "--register"], "Registo da VM")
        executar_vboxmanage(["modifyvm", VM_NAME, "--memory", "4096", "--cpus", "4", "--vram", "128"], "Alocação de CPU/RAM")
        
        disco_path = f"./{VM_NAME}_disk.vdi"
        executar_vboxmanage(["createmedium", "disk", "--filename", disco_path, "--size", "51200", "--format", "VDI"], "Criação de VDI (50GB)")
        executar_vboxmanage(["storagectl", VM_NAME, "--name", "SATA", "--add", "sata", "--controller", "IntelAhci"], "Controladora SATA")
        executar_vboxmanage(["storageattach", VM_NAME, "--storagectl", "SATA", "--port", "0", "--device", "0", "--type", "hdd", "--medium", disco_path], "Mount do Disco")
        
        executar_vboxmanage(["storagectl", VM_NAME, "--name", "IDE", "--add", "ide"], "Controladora IDE")
        executar_vboxmanage(["storageattach", VM_NAME, "--storagectl", "IDE", "--port", "0", "--device", "0", "--type", "dvddrive", "--medium", ISO_PATH], "Mount da ISO")
        
        executar_vboxmanage(["modifyvm", VM_NAME, "--nic1", "bridged", "--bridgeadapter1", "MediaTek Wi-Fi 7 MT7925 Wireless LAN Card"], "Interface de Rede (Bridged)")
        
        comando_unattended = [
            "unattended", "install", VM_NAME, "--iso", ISO_PATH, "--user", GUEST_USER,
            "--password", GUEST_PASS, "--country", "PT", "--time-zone", "UTC",
            "--language", "pt_PT", "--install-additions"
        ]
        executar_vboxmanage(comando_unattended, "Injeção de Configuração Unattended (Preseed)")
        executar_vboxmanage(["startvm", VM_NAME, "--type", "gui"], "Arranque do Processo de Instalação")
        
        print("\n>>> O hipervisor iniciou a VM. A instalação prossegue em background.")
        while True:
            resposta = input("O OS concluiu o bootstrap e encontra-se no ambiente de trabalho? (y/n): ").strip().lower()
            if resposta == 'y':
                print("[INFO] Handshake confirmado. A avançar para configuração pós-instalação...")
                break
            elif resposta == 'n':
                print("Aguardando sincronização... (verifique a consola do VirtualBox)")
                time.sleep(15)
            else:
                print("Input inválido. Utilize 'y' para prosseguir ou 'n' para aguardar.")

        print("\n[INFO] A avaliar baseline atual do sistema (Controlo de Acessos e Serviços)...")

        # Configurações Regionais e Atualização Base
        executar_comando_guest(VM_NAME, GUEST_USER, GUEST_PASS, "localectl set-x11-keymap us", usar_sudo=True)
        executar_comando_guest(VM_NAME, GUEST_USER, GUEST_PASS, "localectl set-locale LANG=pt_PT.UTF-8", usar_sudo=True)
        executar_comando_guest(VM_NAME, GUEST_USER, GUEST_PASS, "export DEBIAN_FRONTEND=noninteractive && apt-get update && apt-get upgrade -y", usar_sudo=True)

        # 1. Instalação e Validação do SSH
        print("\n[INFO] A verificar a presença do serviço OpenSSH Server...")
        is_ssh_installed, _, _ = executar_comando_guest(VM_NAME, GUEST_USER, GUEST_PASS, "dpkg -l | grep -w openssh-server")
        if not is_ssh_installed:
            print("[INFO] OpenSSH Server não está instalado. A proceder à instalação...")
            executar_comando_guest(VM_NAME, GUEST_USER, GUEST_PASS, "export DEBIAN_FRONTEND=noninteractive && apt-get install openssh-server -y", usar_sudo=True)
        
        is_ssh_active, _, _ = executar_comando_guest(VM_NAME, GUEST_USER, GUEST_PASS, "systemctl is-active ssh")
        if not is_ssh_active:
            print("[INFO] A ativar o serviço SSH...")
            executar_comando_guest(VM_NAME, GUEST_USER, GUEST_PASS, "systemctl enable ssh && systemctl start ssh", usar_sudo=True)
        else:
            print("[+] OpenSSH Server ativo e funcional.")

        # 2. Definição Dinâmica do Utilizador Alvo
        TARGET_USER = input("\nIntroduza o nome do utilizador a criar para gerir a máquina (acesso SSH/Web): ").strip()
        
        user_exists, _, _ = executar_comando_guest(VM_NAME, GUEST_USER, GUEST_PASS, f"id -u {TARGET_USER}")
        if not user_exists:
            print(f"[INFO] A criar o utilizador '{TARGET_USER}'...")
            executar_comando_guest(VM_NAME, GUEST_USER, GUEST_PASS, f"useradd -m -s /bin/bash {TARGET_USER}", usar_sudo=True)
        
        executar_comando_guest(VM_NAME, GUEST_USER, GUEST_PASS, "groupadd -f xpto", usar_sudo=True)
        executar_comando_guest(VM_NAME, GUEST_USER, GUEST_PASS, f"usermod -aG xpto {TARGET_USER}", usar_sudo=True)

        # 3. Pacotes Adicionais
        executar_comando_guest(VM_NAME, GUEST_USER, GUEST_PASS, "export DEBIAN_FRONTEND=noninteractive && apt-get install pingus apache2 unzip -y", usar_sudo=True)

        # 4. Implementação de Chaves SSH
        print("\n[INFO] A orquestrar pacotes e a reforçar segurança do sistema (Hardening)...")
        public_bytes_raw = ssh_gen(TARGET_USER, VM_NAME)
        public_key_str = public_bytes_raw.decode('utf-8').strip()

        print("[INFO] A transferir material criptográfico via copyto (VBoxManage)...")
        temp_pub_file = os.path.abspath("temp_key.pub")
        with open(temp_pub_file, "w", encoding="utf-8") as f:
            f.write(public_key_str + "\n")

        cmd_copy = [
            "guestcontrol", VM_NAME, "copyto", temp_pub_file, 
            "--target-directory", "/tmp/authorized_keys", 
            "--username", GUEST_USER, "--password", GUEST_PASS
        ]
        executar_vboxmanage(cmd_copy, "Transferência Segura de Chave Pública")

        executar_comando_guest(VM_NAME, GUEST_USER, GUEST_PASS, f"mkdir -p /home/{TARGET_USER}/.ssh", usar_sudo=True)
        executar_comando_guest(VM_NAME, GUEST_USER, GUEST_PASS, f"mv /tmp/authorized_keys /home/{TARGET_USER}/.ssh/authorized_keys", usar_sudo=True)
        executar_comando_guest(VM_NAME, GUEST_USER, GUEST_PASS, f"chown -R {TARGET_USER}:{TARGET_USER} /home/{TARGET_USER}/.ssh", usar_sudo=True)
        executar_comando_guest(VM_NAME, GUEST_USER, GUEST_PASS, f"chmod 700 /home/{TARGET_USER}/.ssh && chmod 600 /home/{TARGET_USER}/.ssh/authorized_keys", usar_sudo=True)

        if os.path.exists(temp_pub_file):
            os.remove(temp_pub_file)

        # 5. Hardening SSH
        executar_comando_guest(VM_NAME, GUEST_USER, GUEST_PASS, "sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config", usar_sudo=True)
        executar_comando_guest(VM_NAME, GUEST_USER, GUEST_PASS, "sed -i 's/^#*PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config", usar_sudo=True)
        executar_comando_guest(VM_NAME, GUEST_USER, GUEST_PASS, "systemctl restart ssh", usar_sudo=True)

        # 6. Preparação Web Base
        executar_comando_guest(VM_NAME, GUEST_USER, GUEST_PASS, "chown -R root:xpto /var/www/html && chmod -R 775 /var/www/html", usar_sudo=True)
        executar_comando_guest(VM_NAME, GUEST_USER, GUEST_PASS, "wget -O /tmp/template.zip https://www.w3schools.com/w3css/w3css_templates.zip && unzip -o /tmp/template.zip -d /var/www/html/", usar_sudo=True)
        executar_comando_guest(VM_NAME, GUEST_USER, GUEST_PASS, f"ln -sfn /var/www/html /home/{TARGET_USER}/website", usar_sudo=True)

        logging.info("--- FIM DA ORQUESTRAÇÃO ---")
        print(f"\n[OK] Provisionamento e Hardening concluídos com sucesso na conta alvo: '{TARGET_USER}'.")


    # ==========================================
    # OPÇÃO 2: CONFIGURAÇÃO DE VM EXISTENTE
    # ==========================================
    elif opcao == '2':
        VM_NAME = input("\nIdentificador exato da VM no VirtualBox: ").strip()
        
        if not vm_existe(VM_NAME):
            print(f"[ERRO] VM '{VM_NAME}' não localizada no inventário do hipervisor.")
            exit(1)
            
        GUEST_USER = input("Login Account (Sudoer): ").strip()
        GUEST_PASS = getpass.getpass("Root/Sudo Password (oculta): ").strip()
        
        if not vm_em_execucao(VM_NAME):
            print(f"[INFO] A VM '{VM_NAME}' encontra-se suspensa/desligada. Emitindo sinal de wake...")
            executar_vboxmanage(["startvm", VM_NAME, "--type", "gui"], "Power-On da VM")
            print(">>> A aguardar 40 segundos para estabilização do Kernel e serviços de rede...")
            time.sleep(40)
        else:
            print(f"[INFO] VM '{VM_NAME}' ativa. Procedendo com a auditoria de estado.")

        # 1. Obtenção e Seleção de Utilizadores
        print("\n[INFO] A procurar utilizadores disponíveis no sistema...")
        _, output_users, _ = executar_comando_guest(
            VM_NAME, GUEST_USER, GUEST_PASS, 
            "awk -F: '$3 >= 1000 && $1 != \"nobody\" {print $1}' /etc/passwd"
        )
        
        utilizadores = output_users.split('\n') if output_users else []
        print("\n--- Utilizadores Disponíveis ---")
        for idx, usr in enumerate(utilizadores, 1):
            print(f"{idx} - {usr}")
        print(f"{len(utilizadores) + 1} - Criar NOVO utilizador")
        
        escolha = input("\nSelecione o número da opção desejada: ").strip()
        
        try:
            escolha_idx = int(escolha)
            if 1 <= escolha_idx <= len(utilizadores):
                TARGET_USER = utilizadores[escolha_idx - 1]
                print(f"[+] Utilizador selecionado: {TARGET_USER}")
            elif escolha_idx == len(utilizadores) + 1:
                TARGET_USER = input("Introduza o nome do novo utilizador: ").strip()
                new_pass = getpass.getpass(f"Introduza a password para '{TARGET_USER}': ").strip()
                
                print(f"[INFO] A criar o utilizador '{TARGET_USER}'...")
                executar_comando_guest(VM_NAME, GUEST_USER, GUEST_PASS, f"useradd -m -s /bin/bash {TARGET_USER}", usar_sudo=True)
                executar_comando_guest(VM_NAME, GUEST_USER, GUEST_PASS, f"echo '{TARGET_USER}:{new_pass}' | chpasswd", usar_sudo=True)
                print(f"[+] Utilizador '{TARGET_USER}' criado com sucesso.")
            else:
                print("[-] Opção inválida. A abortar.")
                exit(1)
        except ValueError:
            print("[-] Entrada inválida. A abortar.")
            exit(1)

        # 2. Instalação e Validação do SSH
        print("\n[INFO] A verificar a instalação do servidor OpenSSH...")
        is_ssh_installed, _, _ = executar_comando_guest(VM_NAME, GUEST_USER, GUEST_PASS, "dpkg -l | grep -w openssh-server")
        
        if not is_ssh_installed:
            print("[-] OpenSSH Server não está instalado. A instalar agora...")
            executar_comando_guest(VM_NAME, GUEST_USER, GUEST_PASS, "export DEBIAN_FRONTEND=noninteractive && apt-get update && apt-get install openssh-server -y", usar_sudo=True)
        
        is_ssh_active, _, _ = executar_comando_guest(VM_NAME, GUEST_USER, GUEST_PASS, "systemctl is-active ssh")
        if not is_ssh_active:
            print("[-] O serviço SSH não está ativo. A iniciar...")
            executar_comando_guest(VM_NAME, GUEST_USER, GUEST_PASS, "systemctl enable ssh && systemctl start ssh", usar_sudo=True)
        else:
            print("[+] OpenSSH Server encontra-se instalado e ativo.")

        # 3. Gestão de Chaves SSH
        print(f"\n[INFO] A verificar configuração SSH para '{TARGET_USER}'...")
        has_ssh, _, _ = executar_comando_guest(
            VM_NAME, GUEST_USER, GUEST_PASS, 
            f"test -s /home/{TARGET_USER}/.ssh/authorized_keys", usar_sudo=True
        )

        if has_ssh:
            print(f"[+] O utilizador '{TARGET_USER}' já possui uma chave SSH configurada no servidor.")
            priv_key = input("Introduza o caminho local da sua chave privada (ex: private_key_VM_USER.pem): ").strip()
            passphrase = getpass.getpass("Introduza a passphrase da chave (se existir, senão pressione Enter): ").strip()
            print(f"[INFO] Dados de acesso registados para a chave: {priv_key}")
        else:
            print(f"[-] O utilizador '{TARGET_USER}' não tem chave SSH. A gerar e configurar agora...")
            
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
            executar_vboxmanage(cmd_copy, "Transferência Segura de Chave Pública")

            executar_comando_guest(VM_NAME, GUEST_USER, GUEST_PASS, f"mkdir -p /home/{TARGET_USER}/.ssh", usar_sudo=True)
            executar_comando_guest(VM_NAME, GUEST_USER, GUEST_PASS, f"mv /tmp/authorized_keys /home/{TARGET_USER}/.ssh/authorized_keys", usar_sudo=True)
            executar_comando_guest(VM_NAME, GUEST_USER, GUEST_PASS, f"chown -R {TARGET_USER}:{TARGET_USER} /home/{TARGET_USER}/.ssh", usar_sudo=True)
            executar_comando_guest(VM_NAME, GUEST_USER, GUEST_PASS, f"chmod 700 /home/{TARGET_USER}/.ssh && chmod 600 /home/{TARGET_USER}/.ssh/authorized_keys", usar_sudo=True)

            if os.path.exists(temp_pub_file):
                os.remove(temp_pub_file)
            print("[+] Chave SSH transferida e configurada no servidor.")

        # 4. Validação do Serviço Apache Base
        print("\n[INFO] A verificar o serviço Apache2...")
        is_apache_installed, _, _ = executar_comando_guest(VM_NAME, GUEST_USER, GUEST_PASS, "dpkg -l | grep -w apache2")
        
        if not is_apache_installed:
            print("[-] Apache2 não está instalado. A instalar agora...")
            executar_comando_guest(VM_NAME, GUEST_USER, GUEST_PASS, "export DEBIAN_FRONTEND=noninteractive && apt-get update && apt-get install apache2 -y", usar_sudo=True)
        
        is_apache_active, _, _ = executar_comando_guest(VM_NAME, GUEST_USER, GUEST_PASS, "systemctl is-active apache2")
        if not is_apache_active:
            print("[-] Apache2 não está ativo. A iniciar o serviço...")
            executar_comando_guest(VM_NAME, GUEST_USER, GUEST_PASS, "systemctl enable apache2 && systemctl start apache2", usar_sudo=True)
        else:
            print("[+] Apache2 encontra-se instalado e ativo.")
        
        logging.info("--- FIM DA CONFIGURAÇÃO (OPÇÃO 2) ---")
        exit(0)

    else:
        print("[ERRO] Instrução não reconhecida. Processo terminado.")
        exit(1)


if __name__ == "__main__":
    main()
