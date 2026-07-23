#!/usr/bin/env python3
"""
Automated SSL/TLS Provisioning and Apache Configuration Orchestrator.

Este script automatiza a configuração segura de servidores web Apache2 via SSH.
Inclui a geração de certificados autoassinados com suporte a Subject Alternative Name (SAN),
aplicação de hardening em diretórios web e criação de atalhos seguros para gestão remota via SFTP/WinSCP.

Author: Nataniel Bessa
Version: 1.0.2
"""

import os
import paramiko
import logging
import getpass
from typing import Tuple

# ==========================================
# Configuração Global de Logging
# ==========================================
# Formatação padronizada para facilitar auditoria e integração com ferramentas de SIEM/Log Management.
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ssl_config_audit.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

# ==========================================
# Funções Core / Auxiliares
# ==========================================
def executar_sudo(ssh_client: paramiko.SSHClient, sudo_password: str, comando: str) -> Tuple[bool, str, str]:
    """
    Executa comandos no servidor remoto utilizando escalonamento de privilégios (sudo) de forma não-interativa.

    Args:
        ssh_client (paramiko.SSHClient): Instância ativa da ligação SSH.
        sudo_password (str): Palavra-passe de root/sudo do servidor.
        comando (str): Comando shell a ser executado.

    Returns:
        Tuple[bool, str, str]: Retorna um tuplo contendo (Sucesso da Operação, Standard Output, Standard Error).
    """
    comando_escapado = comando.replace('"', '\\"')
    # A injeção via echo pipa para o sudo -S evita o bloqueio do terminal à espera de input interativo.
    comando_final = f"echo '{sudo_password}' | sudo -S bash -c \"{comando_escapado}\""
    
    stdin, stdout, stderr = ssh_client.exec_command(comando_final)
    exit_status = stdout.channel.recv_exit_status()
    
    return exit_status == 0, stdout.read().decode().strip(), stderr.read().decode().strip()

# ==========================================
# Módulos de Orquestração SSL e Web
# ==========================================
def reset_ssl_apache(ssh_client: paramiko.SSHClient, sudo_password: str) -> bool:
    """
    Verifica a presença do Apache2, instala caso necessário e purga configurações SSL obsoletas 
    para garantir um ambiente limpo (idempotência).

    Args:
        ssh_client (paramiko.SSHClient): Instância ativa da ligação SSH.
        sudo_password (str): Palavra-passe de root/sudo do servidor.

    Returns:
        bool: True se o ambiente estiver pronto, False em caso de falha ou cancelamento.
    """
    logging.info("    [*] A verificar a integridade da instalação do Apache2...")
    _, stdout, _ = ssh_client.exec_command("dpkg -l | grep -w apache2")
    
    if "apache2" not in stdout.read().decode():
        logging.warning("    [!] Apache2 não detetado no sistema alvo.")
        resposta = input("    [?] Deseja provisionar o Apache2 agora? (y/n): ").strip().lower()
        
        if resposta == 'y':
            logging.info("    [*] A iniciar instalação do Apache2. Este processo pode demorar...")
            # DEBIAN_FRONTEND=noninteractive suprime prompts que poderiam quebrar a automação.
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


def generate_and_fetch_ssl(ssh_client: paramiko.SSHClient, sudo_password: str, local_dir: str, ssh_user: str, host: str) -> bool:
    """
    Gera chaves RSA de 2048 bits e um certificado autoassinado (x509) com Subject Alternative Name (SAN).
    Realiza o fetch das chaves para a máquina operadora de forma segura via SFTP.

    Args:
        ssh_client (paramiko.SSHClient): Instância ativa da ligação SSH.
        sudo_password (str): Palavra-passe de root/sudo do servidor.
        local_dir (str): Diretório de trabalho local para armazenar o backup do certificado.
        ssh_user (str): Utilizador SSH ativo (para gestão temporária de permissões SFTP).
        host (str): Endereço IP do servidor alvo (utilizado no campo SAN).

    Returns:
        bool: True se a geração e transferência forem bem-sucedidas.
    """
    logging.info("    [*] A gerar par de chaves e certificado x509 (RSA 2048) com suporte SAN...")
    
    cert_subj = f"/C=PT/ST=Local/L=Local/O=Administracao/CN={host}"
    # Inclusão do subjectAltName (SAN) é mandatória para conformidade com browsers modernos (Chrome, Edge, Firefox).
    cmd_ssl = f"openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /tmp/server.key -out /tmp/server.crt -subj '{cert_subj}' -addext 'subjectAltName=IP:{host}'"
    
    sucesso, _, erro = executar_sudo(ssh_client, sudo_password, cmd_ssl)
    if not sucesso:
        logging.error(f"    [-] Falha criptográfica na geração do certificado: {erro}")
        return False
        
    # Rebaixamento temporário de privilégios para permitir a leitura pelo processo SFTP do utilizador normal.
    executar_sudo(ssh_client, sudo_password, f"chown {ssh_user}:{ssh_user} /tmp/server.crt /tmp/server.key")
    
    logging.info("    [*] A extrair certificado público (.crt) e chave privada (.key) para auditoria local...")
    try:
        sftp = ssh_client.open_sftp()
        sftp.get("/tmp/server.crt", os.path.join(local_dir, "server.crt"))
        sftp.get("/tmp/server.key", os.path.join(local_dir, "server.key"))
        sftp.close()
        logging.info(f"    [+] Artefatos criptográficos transferidos com sucesso para: {local_dir}")
    except Exception as e:
        logging.error(f"    [-] Erro na camada SFTP durante transferência: {e}")
        return False

    logging.info("    [*] A aplicar os artefatos nos diretórios definitivos (/etc/ssl/)...")
    executar_sudo(ssh_client, sudo_password, "mv /tmp/server.crt /etc/ssl/certs/apache-selfsigned.crt")
    executar_sudo(ssh_client, sudo_password, "mv /tmp/server.key /etc/ssl/private/apache-selfsigned.key")
    
    # Restauro rigoroso do ownership para root, mitigando riscos de exposição da chave privada.
    executar_sudo(ssh_client, sudo_password, "chown root:root /etc/ssl/private/apache-selfsigned.key /etc/ssl/certs/apache-selfsigned.crt")
    executar_sudo(ssh_client, sudo_password, "chmod 600 /etc/ssl/private/apache-selfsigned.key")
    
    return True


def configure_apache_ssl(ssh_client: paramiko.SSHClient, sudo_password: str, host: str):
    """
    Injeta a configuração do VirtualHost seguro (Porta 443) e ativa os módulos SSLEngine.

    Args:
        ssh_client (paramiko.SSHClient): Instância ativa da ligação SSH.
        sudo_password (str): Palavra-passe de root/sudo do servidor.
        host (str): Endereço IP ou Domínio para a diretiva ServerName.
    """
    logging.info("    [*] A injetar o bloco de configuração VirtualHost (TLS/SSL)...")
    
    # Configuração padronizada para mapear o certificado previamente gerado
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


def setup_winscp_access(ssh_client: paramiko.SSHClient, sudo_password: str, ssh_user: str):
    """
    Aplica políticas de controlo de acessos (Hardening) ao diretório web e cria atalhos 
    seguros para gestão remota de ficheiros via SFTP (ex: WinSCP).

    Args:
        ssh_client (paramiko.SSHClient): Instância ativa da ligação SSH.
        sudo_password (str): Palavra-passe de root/sudo do servidor.
        ssh_user (str): Nome do utilizador SSH alvo.
    """
    logging.info("    [*] A implementar políticas ACL no diretório web e a criar atalhos de gestão...")
    
    # Define o ownership: User tem controlo, grupo www-data (Apache) gere a leitura no backend
    executar_sudo(ssh_client, sudo_password, f"chown -R {ssh_user}:www-data /var/www/html")
    
    # Aplicações de permissões estritas (750): User (rwx), Group (r-x), Others (---)
    executar_sudo(ssh_client, sudo_password, "chmod -R 750 /var/www/html")
    
    # Criação do Symlink (Link Simbólico) na diretoria home do utilizador
    symlink_path = f"/home/{ssh_user}/Gestao_Website"
    executar_sudo(ssh_client, sudo_password, f"ln -sfn /var/www/html {symlink_path}")
    
    # Evita cadeados de bloqueio no WinSCP assegurando que o dono lógico do atalho é o utilizador
    executar_sudo(ssh_client, sudo_password, f"chown -h {ssh_user}:{ssh_user} {symlink_path}")
    
    logging.info(f"    [+] Workspace seguro configurado em: {symlink_path}")

# ==========================================
# Main Execution Flow
# ==========================================
def main():
    logging.info("[*] Início da Orquestração de Infraestrutura Segura (Linux Mint)...")

    print("\n" + "="*60)
    print(" ORQUESTRADOR DE AMBIENTES SSL/TLS - VIA CHAVES ED25519")
    print("="*60)
    
    host = input("Target IP (Linux Mint VM): ").strip()
    user = input(f"Target Username for {host}: ").strip()
    key_path = input("Path for Private SSH Key (.pem): ").strip()
    
    # Utilização de inputs blindados para segredos
    ssh_passphrase = getpass.getpass("SSH Key Passphrase (hidden): ").strip()
    sudo_pwd = getpass.getpass("Sudo/Root Password (hidden): ").strip()
    print("="*60)

    if not os.path.exists(key_path):
        logging.error(f"\n[ERRO CRÍTICO] A chave criptográfica não foi encontrada no path especificado: {key_path}")
        return

    local_dir = os.getcwd() 
    logging.info(f"\n{'-'*60}\n[>] A inicializar handshake SSH (Public Key Authentication) com {host}...")
    
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        # A autenticação depende exclusivamente do par de chaves ED25519 previamente injetado (Password Auth desativada)
        client.connect(
            hostname=host, 
            username=user, 
            key_filename=key_path,
            passphrase=ssh_passphrase, 
            timeout=15
        )
        logging.info("    [+] Handshake SSH concluído com sucesso.")
        
        # Pipeline de Orquestração
        if not reset_ssl_apache(client, sudo_pwd):
            return

        if not generate_and_fetch_ssl(client, sudo_pwd, local_dir, user, host):
            return
            
        configure_apache_ssl(client, sudo_pwd, host)
        setup_winscp_access(client, sudo_pwd, user)
        
    except paramiko.ssh_exception.PasswordRequiredException:
        logging.error("    [-] Acesso Negado: A passphrase fornecida não consegue desencriptar a chave privada.")
    except paramiko.AuthenticationException:
        logging.error("    [-] Acesso Negado: O servidor recusou a chave apresentada ou o utilizador é inválido.")
    except Exception as e:
        logging.error(f"    [-] Falha Crítica na ligação de socket SSH: {e}")
    finally:
        client.close()
        logging.info(f"\n{'-'*60}\n[*] Pipeline de Orquestração finalizado. Sessão TCP encerrada.")

if __name__ == "__main__":
    main()