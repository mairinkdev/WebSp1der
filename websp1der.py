#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WebSp1der - Ferramenta profissional de verificação de vulnerabilidades web
Desenvolvido por: mairinkdev (https://github.com/mairinkdev)
"""

import sys
import os
import argparse
import time
import json
import yaml
import logging
from datetime import datetime
from rich.console import Console
from rich.progress import Progress
from rich.panel import Panel
from rich.table import Table
from modules.scanner import Scanner
from modules.reporter import Reporter
from modules.utils import Utils

# Configuração do logger
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='websp1der.log'
)
logger = logging.getLogger('websp1der')

# Configurar aviso de urllib3 (desabilitar avisos de SSL)
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Console para saída formatada
console = Console()

def print_banner():
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
    """
    console.print(Panel(banner, border_style="green"))

def parse_arguments():
    """Parse os argumentos da linha de comando."""
    parser = argparse.ArgumentParser(
        description='WebSp1der - Ferramenta de análise de vulnerabilidades web',
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument('-u', '--url', required=True, help='URL alvo para análise')
    parser.add_argument('-a', '--analyze', default='basic', 
                        choices=['basic', 'full', 'custom'],
                        help='Tipo de análise (basic, full, custom)')
    parser.add_argument('-o', '--output', help='Arquivo de saída para o relatório')
    parser.add_argument('-v', '--verbose', action='store_true', 
                        help='Aumenta o nível de detalhes na saída')
    parser.add_argument('-t', '--threads', type=int, default=5,
                        help='Número de threads para análise paralela')
    parser.add_argument('-p', '--proxy', help='Usar proxy (formato: http://host:porta)')
    parser.add_argument('-c', '--config', help='Arquivo de configuração personalizado')
    
    return parser.parse_args()

def load_config(config_file=None):
    """Carrega as configurações do arquivo YAML."""
    default_config = os.path.join(os.path.dirname(__file__), 'config', 'default.yaml')
    
    if config_file and os.path.exists(config_file):
        with open(config_file, 'r') as f:
            return yaml.safe_load(f)
    elif os.path.exists(default_config):
        with open(default_config, 'r') as f:
            return yaml.safe_load(f)
    else:
        logger.warning("Arquivo de configuração não encontrado. Usando configurações padrão.")
        return {}

def main():
    """Função principal do programa."""
    print_banner()
    args = parse_arguments()
    
    # Configuração do logger
    if args.verbose:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(levelname)s - %(message)s')
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        logger.setLevel(logging.DEBUG)
    
    # Carregar configurações
    config = load_config(args.config)
    
    # Iniciar o relógio
    start_time = time.time()
    
    try:
        console.print(f"[bold cyan]Iniciando análise em:[/] [bold yellow]{args.url}[/]")
        console.print(f"[bold cyan]Modo de análise:[/] [bold yellow]{args.analyze}[/]")
        
        # Iniciar scanner
        scanner = Scanner(
            url=args.url,
            scan_type=args.analyze,
            threads=args.threads,
            proxy=args.proxy,
            config=config
        )
        
        # Executar verificações
        with Progress() as progress:
            task = progress.add_task("[cyan]Analisando...", total=100)
            results = scanner.run(progress, task)
        
        # Gerar relatório
        reporter = Reporter(results, args.url, args.analyze)
        report = reporter.generate()
        
        if args.output:
            reporter.save_report(args.output, report)
            console.print(f"[bold green]Relatório salvo em:[/] {args.output}")
        
        # Mostrar um resumo dos resultados
        vulnerabilities = results.get('vulnerabilities', [])
        total_vulns = len(vulnerabilities)
        
        table = Table(title="Resumo de Vulnerabilidades")
        table.add_column("Severidade", style="cyan")
        table.add_column("Quantidade", style="magenta")
        
        severity_count = {"Crítica": 0, "Alta": 0, "Média": 0, "Baixa": 0, "Informativa": 0}
        for vuln in vulnerabilities:
            if vuln['severity'] == 'critical':
                severity_count["Crítica"] += 1
            elif vuln['severity'] == 'high':
                severity_count["Alta"] += 1
            elif vuln['severity'] == 'medium':
                severity_count["Média"] += 1
            elif vuln['severity'] == 'low':
                severity_count["Baixa"] += 1
            elif vuln['severity'] == 'info':
                severity_count["Informativa"] += 1
        
        for sev, count in severity_count.items():
            table.add_row(sev, str(count))
        
        console.print(table)
        
        if total_vulns > 0:
            console.print(f"[bold red]Total de vulnerabilidades encontradas:[/] {total_vulns}")
        else:
            console.print("[bold green]Nenhuma vulnerabilidade encontrada.[/]")
        
    except KeyboardInterrupt:
        console.print("\n[bold red]Análise interrompida pelo usuário.[/]")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Erro durante a execução: {str(e)}", exc_info=True)
        console.print(f"[bold red]Erro:[/] {str(e)}")
        sys.exit(1)
    finally:
        elapsed_time = time.time() - start_time
        console.print(f"[bold cyan]Tempo total de execução:[/] {elapsed_time:.2f} segundos")

if __name__ == "__main__":
    main() 