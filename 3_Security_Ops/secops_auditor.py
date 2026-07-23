#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SecOps Compliance & Health Auditor.

Este script atua como um agente sem agente (agentless auditor). Liga-se remotamente
via SSH utilizando chaves ED25519, interroga a configuração de serviços críticos 
(Apache, OpenSSL, OpenSSH, permissões de utilizadores) e gera um relatório HTML 
de conformidade de segurança localmente.

Author: Nataniel Bessa
Version: 1.0.2
Context: Automated Infrastructure & Security Compliance
"""

import paramiko
import logging
import getpass
import os
import datetime
from typing import Dict, Any

# ==========================================
# Configuração Global de Logging
# ==========================================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('audit_execution.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

# ==========================================
# Motor de Auditoria (Queries de Sistema)
# ==========================================
def executar_query_segura(ssh_client: paramiko.SSHClient, comando: str) -> str:
    """Executa um comando de leitura no servidor e devolve o output tratado."""
    stdin, stdout, stderr = ssh_client.exec_command(comando)
    return stdout.read().decode().strip()

def auditar_ssh_hardening(ssh_client: paramiko.SSHClient) -> Dict[str, Any]:
    """Audita a configuração do serviço OpenSSH."""
    logging.info("    [*] A avaliar políticas de autenticação SSH (sshd_config)...")
    
    # Procura pela linha ativa (sem comentários) de PasswordAuthentication
    pwd_auth = executar_query_segura(ssh_client, "grep -iE '^PasswordAuthentication' /etc/ssh/sshd_config")
    # Procura pela linha ativa de PermitRootLogin
    root_login = executar_query_segura(ssh_client, "grep -iE '^PermitRootLogin' /etc/ssh/sshd_config")

    is_pwd_disabled = "no" in pwd_auth.lower()
    is_root_disabled = "no" in root_login.lower() or "prohibit-password" in root_login.lower()

    return {
        "password_auth": pwd_auth if pwd_auth else "Não explicitamente definida",
        "password_auth_pass": is_pwd_disabled,
        "root_login": root_login if root_login else "Não explicitamente definida",
        "root_login_pass": is_root_disabled
    }

def auditar_ssl_apache(ssh_client: paramiko.SSHClient) -> Dict[str, Any]:
    """Audita o estado do Apache, módulo SSL e validade do certificado x509."""
    logging.info("    [*] A verificar integridade do Servidor Web e Criptografia em trânsito...")
    
    ssl_mod = executar_query_segura(ssh_client, "ls /etc/apache2/mods-enabled | grep ssl")
    ssl_enabled = "ssl" in ssl_mod
    
    # Extrai a data de expiração do certificado TLS gerado no Script 2
    cert_path = "/etc/ssl/certs/apache-selfsigned.crt"
    cert_exists = executar_query_segura(ssh_client, f"test -f {cert_path} && echo 'EXISTS' || echo 'MISSING'")
    
    expiry_date = "N/A"
    cert_valid = False
    if cert_exists == "EXISTS":
        expiry_raw = executar_query_segura(ssh_client, f"openssl x509 -enddate -noout -in {cert_path}")
        expiry_date = expiry_raw.replace("notAfter=", "")
        cert_valid = True

    return {
        "ssl_module_enabled": ssl_enabled,
        "certificate_expiry": expiry_date,
        "certificate_pass": cert_valid
    }

def auditar_privilegios(ssh_client: paramiko.SSHClient) -> Dict[str, Any]:
    """Lista utilizadores com privilégios de escalonamento (Sudoers)."""
    logging.info("    [*] A auditar Identidades e Controlo de Acesso (Sudo group)...")
    sudoers = executar_query_segura(ssh_client, "getent group sudo | cut -d: -f4")
    return {
        "sudo_users": sudoers.split(",") if sudoers else []
    }

# ==========================================
# Gerador de Relatório HTML
# ==========================================
def gerar_relatorio_html(host: str, ssh_data: dict, ssl_data: dict, priv_data: dict):
    """Compila os dados recolhidos num dashboard HTML estilizado."""
    logging.info("    [*] A gerar Security Compliance Report (HTML)...")
    
    data_hora = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Lógica de formatação de cores (Pass = Verde, Fail = Vermelho)
    def c(status): return "#28a745" if status else "#dc3545"
    def i(status): return "PASS" if status else "FAIL"

    html_content = f"""
    <!DOCTYPE html>
    <html lang="pt-PT">
    <head>
        <meta charset="UTF-8">
        <title>SecOps Report - {host}</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f7f6; color: #333; margin: 0; padding: 20px; }}
            .container {{ max-width: 800px; margin: auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
            h1 {{ border-bottom: 2px solid #0056b3; padding-bottom: 10px; color: #0056b3; }}
            .metadata {{ font-size: 0.9em; color: #666; margin-bottom: 30px; }}
            .section {{ margin-bottom: 25px; }}
            .section h2 {{ font-size: 1.2em; background: #eee; padding: 10px; border-radius: 5px; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
            th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
            th {{ background-color: #f8f9fa; width: 40%; }}
            .badge {{ padding: 5px 10px; color: white; border-radius: 4px; font-weight: bold; font-size: 0.9em; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Auditoria de Conformidade e Segurança</h1>
            <div class="metadata">
                <p><strong>Alvo (Target IP):</strong> {host}</p>
                <p><strong>Data da Auditoria:</strong> {data_hora}</p>
                <p><strong>Motor de Auditoria:</strong> Automated SecOps Python Probe</p>
            </div>

            <div class="section">
                <h2>1. Superfície de Ataque SSH (Hardening)</h2>
                <table>
                    <tr>
                        <th>Password Authentication</th>
                        <td><span class="badge" style="background-color: {c(ssh_data['password_auth_pass'])}">{i(ssh_data['password_auth_pass'])}</span></td>
                    </tr>
                    <tr>
                        <th>Root Login Permission</th>
                        <td><span class="badge" style="background-color: {c(ssh_data['root_login_pass'])}">{i(ssh_data['root_login_pass'])}</span></td>
                    </tr>
                </table>
            </div>

            <div class="section">
                <h2>2. Criptografia em Trânsito (Apache SSL)</h2>
                <table>
                    <tr>
                        <th>Módulo SSL (Apache2)</th>
                        <td><span class="badge" style="background-color: {c(ssl_data['ssl_module_enabled'])}">{i(ssl_data['ssl_module_enabled'])}</span></td>
                    </tr>
                    <tr>
                        <th>Validade do Certificado (x509)</th>
                        <td>{ssl_data['certificate_expiry']}</td>
                    </tr>
                </table>
            </div>

            <div class="section">
                <h2>3. Identidades e Privilégios (Sudoers)</h2>
                <table>
                    <tr>
                        <th>Contas com acesso Sudo</th>
                        <td>{", ".join(priv_data['sudo_users']) if priv_data['sudo_users'] else "Nenhum utilizador detetado"}</td>
                    </tr>
                </table>
            </div>
        </div>
    </body>
    </html>
    """

    filename = f"SecOps_Report_{host.replace('.', '_')}.html"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html_content)
    
    logging.info(f"    [+] Relatório gerado com sucesso: {os.path.abspath(filename)}")

# ==========================================
# Fluxo de Execução
# ==========================================
def main():
    logging.info("[*] A iniciar SecOps Compliance Auditor...")

    print("\n" + "="*60)
    print(" AUDITORIA DE SEGURANÇA E CONFORMIDADE (AGENTLESS)")
    print("="*60)
    
    host = input("Target IP (Linux Mint VM): ").strip()
    user = input(f"Auditor Username for {host}: ").strip()
    key_path = input("Path for Private SSH Key (.pem): ").strip()
    
    ssh_passphrase = getpass.getpass("SSH Key Passphrase (hidden): ").strip()
    print("="*60)

    if not os.path.exists(key_path):
        logging.error(f"\n[ERRO CRÍTICO] A chave criptográfica não foi encontrada: {key_path}")
        return

    logging.info(f"\n{'-'*60}\n[>] A estabelecer handshake SSH para Auditoria em {host}...")
    
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        client.connect(
            hostname=host, 
            username=user, 
            key_filename=key_path,
            passphrase=ssh_passphrase, 
            timeout=15
        )
        logging.info("    [+] Ligação estabelecida. A iniciar extração de telemetria...")
        
        # Orquestração das queries de auditoria
        ssh_data = auditar_ssh_hardening(client)
        ssl_data = auditar_ssl_apache(client)
        priv_data = auditar_privilegios(client)
        
        # Geração do artefacto final
        gerar_relatorio_html(host, ssh_data, ssl_data, priv_data)
        
    except paramiko.AuthenticationException:
        logging.error("    [-] Autenticação falhou. A chave ou a passphrase estão incorretas.")
    except Exception as e:
        logging.error(f"    [-] Erro durante a auditoria: {e}")
    finally:
        client.close()
        logging.info(f"\n{'-'*60}\n[*] SecOps Scan concluído. Conexão TCP encerrada.")

if __name__ == "__main__":
    main()