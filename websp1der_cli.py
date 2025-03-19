#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WebSp1der - Intermediador entre interface web e linha de comando
Desenvolvido por: mairinkdev (https://github.com/mairinkdev)
"""

import os
import sys
import platform
import subprocess
import argparse

def detect_os():
    """Detecta o sistema operacional em que o script está sendo executado."""
    sistema = platform.system().lower()
    if sistema == 'windows':
        return 'windows'
    elif sistema in ['linux', 'darwin']:
        return 'unix'
    else:
        return 'desconhecido'

def limpar_tela():
    """Limpa a tela do terminal de acordo com o sistema operacional."""
    if detect_os() == 'windows':
        os.system('cls')
    else:
        os.system('clear')

def imprimir_banner():
    """Exibe o banner da aplicação."""
    banner = r"""
 __      __      ___.    _________      .__    .___            
/  \    /  \ ____\_ |__  /   _____/_____ |__| __| _/___________
\   \/\/   // __ \| __ \ \_____  \\____ \|  |/ __ |/ __ \_  __ \
 \        /\  ___/| \_\ \/        \  |_> >  / /_/ \  ___/|  | \/
  \__/\  /  \___  >___  /_______  /   __/|__\____ |\___  >__|   
       \/       \/    \/        \/|__|           \/    \/       
       
WebSp1der v1.0.0 - Ferramenta de Análise de Vulnerabilidades Web
Desenvolvido por: mairinkdev (https://github.com/mairinkdev)
Sistema Operacional detectado: {0}
    """.format("Windows" if detect_os() == 'windows' else "Linux/Unix")
    
    print(banner)
    print("-" * 70)

def perguntar_modo_uso():
    """Pergunta ao usuário se deseja usar a interface web ou linha de comando."""
    print("\nComo você gostaria de usar o WebSp1der?")
    print("1. Interface Web (acesso através do navegador)")
    print("2. Linha de Comando (terminal/PowerShell)")
    
    while True:
        try:
            opcao = input("\nEscolha uma opção (1/2): ").strip()
            if opcao == '1':
                return 'web'
            elif opcao == '2':
                return 'cli'
            else:
                print("Opção inválida. Por favor, digite 1 ou 2.")
        except KeyboardInterrupt:
            print("\nOperação cancelada pelo usuário.")
            sys.exit(0)

def iniciar_interface_web():
    """Inicia a interface web do WebSp1der."""
    print("\nIniciando interface web...")
    print("Para acessar, abra seu navegador e vá para: http://localhost:5000")
    print("Pressione Ctrl+C para encerrar o servidor quando terminar.\n")
    
    try:
        # Executa o script app_interface.py
        subprocess.run([sys.executable, "app_interface.py"])
    except KeyboardInterrupt:
        print("\nServidor web encerrado.")
    except Exception as e:
        print(f"\nErro ao iniciar a interface web: {str(e)}")
        sys.exit(1)

def iniciar_linha_comando(args=None):
    """Inicia o modo de linha de comando do WebSp1der."""
    print("\nIniciando modo de linha de comando...")
    
    if args:
        # Se recebeu argumentos, passa-os diretamente para o app.py
        cmd = [sys.executable, "app.py"] + args
        try:
            subprocess.run(cmd)
        except KeyboardInterrupt:
            print("\nOperação cancelada pelo usuário.")
        except Exception as e:
            print(f"\nErro ao executar o comando: {str(e)}")
    else:
        # Se não recebeu argumentos, exibe ajuda para o usuário
        print("\nPara usar o WebSp1der em modo de linha de comando, você precisa especificar uma URL alvo.")
        print("Exemplo básico: python app.py -u https://exemplo.com\n")
        
        # Pergunta se deseja ver a ajuda completa
        try:
            ver_ajuda = input("Deseja ver as opções disponíveis? (s/n): ").strip().lower()
            if ver_ajuda == 's':
                subprocess.run([sys.executable, "app.py", "-h"])
            
            # Pergunta se deseja executar um comando personalizado
            executar = input("\nDeseja executar um escaneamento agora? (s/n): ").strip().lower()
            if executar == 's':
                url = input("URL alvo: ").strip()
                if not url:
                    print("URL não especificada. Encerrando.")
                    return
                
                tipo_scan = input("Tipo de escaneamento (basic/full/xss/sqli/headers/port/csrf/info) [basic]: ").strip() or "basic"
                threads = input("Número de threads [5]: ").strip() or "5"
                output = input("Arquivo de saída (opcional): ").strip()
                proxy = input("Proxy (opcional, formato http://host:porta): ").strip()
                
                # Montar comando
                cmd = [sys.executable, "app.py", "-u", url, "-a", tipo_scan, "-t", threads]
                if output:
                    cmd.extend(["-o", output])
                if proxy:
                    cmd.extend(["-p", proxy])
                
                # Executar comando
                try:
                    subprocess.run(cmd)
                except KeyboardInterrupt:
                    print("\nOperação cancelada pelo usuário.")
                except Exception as e:
                    print(f"\nErro ao executar o comando: {str(e)}")
        except KeyboardInterrupt:
            print("\nOperação cancelada pelo usuário.")

def main():
    """Função principal."""
    limpar_tela()
    imprimir_banner()
    
    # Verificar se foram passados argumentos
    if len(sys.argv) > 1:
        # Se recebeu argumentos, passa diretamente para o app.py (modo CLI)
        iniciar_linha_comando(sys.argv[1:])
    else:
        # Perguntar ao usuário como deseja usar a ferramenta
        modo = perguntar_modo_uso()
        
        if modo == 'web':
            iniciar_interface_web()
        else:
            iniciar_linha_comando()

if __name__ == "__main__":
    main() 