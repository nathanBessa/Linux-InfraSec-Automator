#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Automated SSL/TLS Provisioning and Apache Configuration Orchestrator.

Este script automatiza a configuração segura de servidores web Apache2 via SSH.
Utiliza a API local do VirtualBox (VBoxManage) para Discovery e estabelece túneis 
SSH nativos com conta Administradora para Deployment (Hardening, SSL e ACLs),
delegando no final os acessos estritos ao utilizador alvo (Role Separation).

Author: Nataniel Bessa
Version: 1.1.0
"""

import os
import paramiko
import logging
import getpass
import subprocess
from typing import Tuple, List

# ==========================================
# Configurações Globais e Paths
# ==========================================
VBOX_PATH = r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"

if not os.path.exists(VBOX_PATH):
    raise FileNotFoundError(
        f"\n[ERRO CRÍTICO] O executável VBoxManage não foi encontrado em: {VBOX_PATH}\n"
        "Verifique a pasta de instalação do Oracle VirtualBox."
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
# Camada de Interação Local (VirtualBox API)
# ==========================================
def executar_vboxmanage(comandos: List[str], descricao: str, ignorar_erro: bool = False) -> Tuple[bool, str]:
    comando_completo = [VBOX_PATH] + comandos
    try:
        resultado = subprocess.run(comando_completo, check=True, capture_output=True, text=True)
        return True, resultado.stdout.strip()
    except subprocess.CalledProcessError as erro:
        if not ignorar_erro:
            logging.error(f"Falha ao executar VBoxManage: {descricao} - Erro: {erro.stderr.strip()}")
        return False, erro.stderr.strip()

def executar_comando_guest(vm_nome: str, user: str, password: str, comando: str) -> Tuple[bool, str, str]:
    cmd = [
        "guestcontrol", vm_nome, "run", 
        "--exe", "/bin/bash", 
        "--username", user, 
        "--password", password, 
        "--", "-c", comando
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
# Camada de Execução Remota (SSH / Web)
# ==========================================
def executar_sudo(ssh_client: paramiko.SSHClient, sudo_password: str, comando: str) -> Tuple[bool, str, str]:
    comando_escapado = comando.replace('"', '\\"')
    comando_final = f"echo '{sudo_password}' | sudo -S bash -c \"{comando_escapado}\""
    
    stdin, stdout, stderr = ssh_client.exec_command(comando_final)
    exit_status = stdout.channel.recv_exit_status()
    
    return exit_status == 0, stdout.read().decode().strip(), stderr.read().decode().strip()

def reset_ssl_apache(ssh_client: paramiko.SSHClient, sudo_password: str) -> bool:
    logging.info("    [*] A verificar a integridade da instalação do Apache2...")
    _, stdout, _ = ssh_client.exec_command("dpkg -l | grep -w apache2")
    
    if "apache2" not in stdout.read().decode():
        logging.warning("    [!] Apache2 não detetado no sistema alvo.")
        resposta = input("    [?] Deseja provisionar o Apache2 agora? (y/n): ").strip().lower()
        
        if resposta == 'y':
            logging.info("    [*] A iniciar instalação do Apache2. Este processo pode demorar...")
            comando_instalar = "export DEBIAN_FRONTEND=noninteractive && apt-get update && apt-get install apache2 -y"
            sucesso, _, err = executar_sudo(ssh_client, sudo_password, comando_instalar)
            
            if not sucesso:
                logging.error(f"    [-] Falha no provisionamento do Apache2: {err}")
                return False
            logging.info("    [+] Apache2 provisionado com sucesso.")
        else:
            logging.error("    [-] Instalação cancelada pelo utilizador. Abortando orquestração SSL.")
            return False
    else:
        logging.info("    [+] Serviço Apache2 localizado.")
        
    logging.info("    [*] A purgar configurações SSL residuais (Reset de Estado)...")
    comandos_reset = [
        "a2dismod ssl || true",
        "a2dissite default-ssl || true",
        "a2dissite custom-ssl || true",
        "rm -f /etc/apache2/sites-available/custom-ssl.conf",
        "systemctl reload apache2 || true"
    ]
    
    for cmd in comandos_reset:
        executar_sudo(ssh_client, sudo_password, cmd)
        
    logging.info("    [+] Ambiente web preparado para injeção de novos certificados.")
    return True

# Modificação nos parâmetros: adição de vm_name e target_user
def generate_and_fetch_ssl(ssh_client: paramiko.SSHClient, sudo_password: str, local_dir: str, admin_user: str, host: str, vm_name: str, target_user: str) -> bool:
    logging.info("    [*] A gerar par de chaves e certificado x509 (RSA 2048) com suporte SAN...")
    
    cert_subj = f"/C=PT/ST=Local/L=Local/O=Administracao/CN={host}"
    cmd_ssl = f"openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /tmp/server.key -out /tmp/server.crt -subj '{cert_subj}' -addext 'subjectAltName=IP:{host}'"
    
    sucesso, _, erro = executar_sudo(ssh_client, sudo_password, cmd_ssl)
    if not sucesso:
        logging.error(f"    [-] Falha criptográfica na geração do certificado: {erro}")
        return False
        
    # O chown é feito para o admin temporariamente para que o SFTP consiga extraí-lo
    executar_sudo(ssh_client, sudo_password, f"chown {admin_user}:{admin_user} /tmp/server.crt /tmp/server.key")
    
    # Construção dinâmica dos nomes dos ficheiros baseados na VM e no Utilizador
    local_crt_name = f"certificado_{vm_name}_{target_user}.crt"
    local_key_name = f"chave_{vm_name}_{target_user}.key"

    logging.info(f"    [*] A extrair certificado público e chave privada para auditoria local ({local_crt_name})...")
    try:
        sftp = ssh_client.open_sftp()
        sftp.get("/tmp/server.crt", os.path.join(local_dir, local_crt_name))
        sftp.get("/tmp/server.key", os.path.join(local_dir, local_key_name))
        sftp.close()
        logging.info(f"    [+] Artefatos criptográficos transferidos com sucesso para: {local_dir}")
    except Exception as e:
        logging.error(f"    [-] Erro na camada SFTP durante transferência: {e}")
        return False

    logging.info("    [*] A aplicar os artefatos nos diretórios definitivos (/etc/ssl/)...")
    executar_sudo(ssh_client, sudo_password, "mv /tmp/server.crt /etc/ssl/certs/apache-selfsigned.crt")
    executar_sudo(ssh_client, sudo_password, "mv /tmp/server.key /etc/ssl/private/apache-selfsigned.key")
    
    executar_sudo(ssh_client, sudo_password, "chown root:root /etc/ssl/private/apache-selfsigned.key /etc/ssl/certs/apache-selfsigned.crt")
    executar_sudo(ssh_client, sudo_password, "chmod 600 /etc/ssl/private/apache-selfsigned.key")
    
    return True

def configure_apache_ssl(ssh_client: paramiko.SSHClient, sudo_password: str, host: str):
    logging.info("    [*] A injetar o bloco de configuração VirtualHost (TLS/SSL)...")
    
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
    executar_sudo(ssh_client, sudo_password, vhost_cmd)
    executar_sudo(ssh_client, sudo_password, "mv /tmp/custom-ssl.conf /etc/apache2/sites-available/custom-ssl.conf")
    
    comandos_ativacao = [
        "a2enmod ssl",
        "a2ensite custom-ssl",
        "systemctl restart apache2"
    ]
    
    for cmd in comandos_ativacao:
        executar_sudo(ssh_client, sudo_password, cmd)
        
    logging.info("    [+] Engine SSL ativado. O servidor está a escutar tráfego encriptado na porta 443.")

def setup_winscp_access(ssh_client: paramiko.SSHClient, sudo_password: str, target_user: str):
    logging.info("    [*] A implementar políticas ACL no diretório web e a criar atalhos de gestão...")
    
    # O utilizador alvo (sem sudo) passa a ser o dono da pasta web
    executar_sudo(ssh_client, sudo_password, f"chown -R {target_user}:www-data /var/www/html")
    executar_sudo(ssh_client, sudo_password, "chmod -R 750 /var/www/html")
    
    symlink_path = f"/home/{target_user}/Gestao_Website"
    executar_sudo(ssh_client, sudo_password, f"ln -sfn /var/www/html {symlink_path}")
    executar_sudo(ssh_client, sudo_password, f"chown -h {target_user}:{target_user} {symlink_path}")
    
    logging.info(f"    [+] Workspace seguro configurado com sucesso para '{target_user}' em: {symlink_path}")

# ==========================================
# Main Execution Flow
# ==========================================
def main():
    logging.info("[*] Início da Orquestração de Infraestrutura Segura (Linux Mint)...")

    logging.info("="*60)
    logging.info(" ORQUESTRADOR DE AMBIENTES SSL/TLS")
    logging.info("="*60)
    
    vm_name = input("Introduza o nome da VM alvo no VirtualBox: ").strip()
    
    if not vm_existe(vm_name):
        logging.error(f"[-] A VM '{vm_name}' não foi encontrada no hipervisor.")
        return
        
    if not vm_em_execucao(vm_name):
        logging.error(f"[-] A VM '{vm_name}' está desligada. Inicie-a primeiro.")
        return

    # 1. Credenciais do Administrador (Serão usadas para GuestControl e SSH)
    logging.info(f"    [*] Forneça as credenciais de ADMINISTRADOR da VM '{vm_name}' para orquestração.")
    admin_user = input("Conta Administrador (Sudoer): ").strip()
    admin_pass = getpass.getpass("Password Administrador (OS/Sudo - oculta): ").strip()
    
    tem_chave_admin = input("O Administrador autentica-se no SSH via chave? (s/n): ").strip().lower()
    admin_key_path = None
    admin_ssh_passphrase = None

    if tem_chave_admin == 's':
        admin_key_path = input("Caminho para a Chave Privada SSH (.pem): ").strip()
        admin_ssh_passphrase = getpass.getpass("SSH Key Passphrase (oculta): ").strip()

    # 2. Discovery do Endereço IP
    logging.info("    [*] A extrair endereço IP via VirtualBox Guest Additions...")
    sucesso_ip, output_ip, err_ip = executar_comando_guest(vm_name, admin_user, admin_pass, "hostname -I | awk '{print $1}'")
    
    if not sucesso_ip or not output_ip:
        logging.error(f"    [-] Falha ao obter IP. Verifique as credenciais ou as Guest Additions. Erro: {err_ip}")
        return
        
    host_ip = output_ip.strip()
    logging.info(f"    [+] Endereço IP Operacional Detetado: {host_ip}")

    # 3. Enumeração de Utilizadores
    logging.info("    [*] A enumerar as identidades válidas no sistema...")
    sucesso_users, output_users, _ = executar_comando_guest(
        vm_name, admin_user, admin_pass, 
        "awk -F: '$3 >= 1000 && $1 != \"nobody\" {print $1}' /etc/passwd"
    )
    
    if not sucesso_users or not output_users:
        logging.error("    [-] Nenhum utilizador válido detetado ou acesso negado.")
        return

    utilizadores = [u.strip() for u in output_users.split('\n') if u.strip()]

    # 4. Seleção de Utilizador Alvo (Role Separation)
    logging.info("--- Utilizadores Disponíveis ---")
    for idx, usr in enumerate(utilizadores, 1):
        logging.info(f"{idx} - {usr}")
        
    try:
        escolha = int(input("\nSelecione o número do utilizador ALVO que vai gerir o site: ").strip())
        if 1 <= escolha <= len(utilizadores):
            target_user = utilizadores[escolha - 1]
            logging.info(f"    [+] Utilizador alvo selecionado: {target_user}")
        else:
            logging.error("[-] Opção inválida. A abortar.")
            return
    except ValueError:
        logging.error("[-] Entrada inválida. A abortar.")
        return

    logging.info("="*60)

    # 5. Handshake SSH (Como Administrador)
    local_dir = os.getcwd() 
    logging.info(f"    [>] A inicializar handshake SSH para {host_ip} com a conta ADMINISTRADOR ({admin_user})...")
    
    admin_client = paramiko.SSHClient()
    admin_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        if tem_chave_admin == 's':
            if not os.path.exists(admin_key_path):
                logging.error(f"\n[ERRO CRÍTICO] A chave não foi encontrada no path especificado: {admin_key_path}")
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
            
        logging.info("    [+] Handshake SSH concluído com sucesso.")
        
        # Pipeline Core (Delegando o target_user no final)
        if not reset_ssl_apache(admin_client, admin_pass):
            return

        # Chamada à função atualizada com a injeção do vm_name e target_user
        if not generate_and_fetch_ssl(admin_client, admin_pass, local_dir, admin_user, host_ip, vm_name, target_user):
            return
            
        configure_apache_ssl(admin_client, admin_pass, host_ip)
        setup_winscp_access(admin_client, admin_pass, target_user)
        
    except paramiko.ssh_exception.PasswordRequiredException:
        logging.error("    [-] Acesso Negado: A passphrase fornecida não consegue desencriptar a chave privada.")
    except paramiko.AuthenticationException:
        logging.error("    [-] Acesso Negado: Falha na autenticação SSH do Administrador.")
    except Exception as e:
        logging.error(f"    [-] Falha Crítica na ligação de socket SSH: {e}")
    finally:
        admin_client.close()
        logging.info(f"\n{'-'*60}\n[*] Pipeline de Orquestração finalizado. Sessão TCP encerrada.")

if __name__ == "__main__":
    main()
