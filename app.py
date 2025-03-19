#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WebSp1der - Versão sem interface
Desenvolvido por: mairinkdev (https://github.com/mairinkdev)
"""

import sys
import os
import argparse
from websp1der import WebSp1der

def parse_arguments():
    """Parse os argumentos da linha de comando."""
    parser = argparse.ArgumentParser(
        description='WebSp1der - Ferramenta de análise de vulnerabilidades web',
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument('-u', '--url', required=True, help='URL alvo para análise')
    parser.add_argument('-a', '--analyze', default='basic', 
                        choices=['basic', 'full', 'custom', 'xss', 'sqli', 'headers', 'port', 'csrf', 'info'],
                        help='Tipo de análise')
    parser.add_argument('-o', '--output', help='Arquivo de saída para o relatório')
    parser.add_argument('-t', '--threads', type=int, default=5,
                        help='Número de threads para análise paralela')
    parser.add_argument('-p', '--proxy', help='Usar proxy (formato: http://host:porta)')
    parser.add_argument('-c', '--config', help='Arquivo de configuração personalizado')
    
    return parser.parse_args()

def main():
    """Função principal do programa."""
    args = parse_arguments()
    
    # Configurar proxy
    proxies = None
    if args.proxy:
        proxies = {
            'http': args.proxy,
            'https': args.proxy
        }
    
    print("WebSp1der - Iniciando escaneamento simples (sem interface)")
    print(f"URL alvo: {args.url}")
    print(f"Tipo de análise: {args.analyze}")
    
    try:
        # Usar a classe WebSp1der
        webspider = WebSp1der()
        
        # Executar o escaneamento
        results = webspider.scan(
            url=args.url, 
            scan_type=args.analyze,
            proxies=proxies,
            threads=args.threads
        )
        
        # Exibir resultados
        vulnerabilities = results.get('vulnerabilities', [])
        total_vulns = len(vulnerabilities)
        
        print("\n=== RESULTADOS ===")
        print(f"Total de vulnerabilidades encontradas: {total_vulns}")
        
        # Contagem por severidade
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
            print(f"{sev}: {count}")
        
        # Salvar relatório se solicitado
        if args.output:
            import json
            os.makedirs(os.path.dirname(args.output) or '.', exist_ok=True)
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=4, ensure_ascii=False)
            print(f"\nRelatório salvo em: {args.output}")
            
    except KeyboardInterrupt:
        print("\nAnálise interrompida pelo usuário.")
        sys.exit(1)
    except Exception as e:
        print(f"Erro: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main() 