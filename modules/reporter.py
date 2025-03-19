#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WebSp1der - Módulo de Geração de Relatórios
Desenvolvido por: mairinkdev (https://github.com/mairinkdev)
"""

import os
import json
import logging
import time
from datetime import datetime
import yaml
from rich.console import Console
from rich.table import Table

logger = logging.getLogger('websp1der.reporter')
console = Console()

class Reporter:
    """Classe para geração de relatórios de escaneamento."""
    
    def __init__(self, scan_results, target_url, scan_type):
        """
        Inicializa o gerador de relatórios.
        
        Args:
            scan_results (dict): Resultados do escaneamento
            target_url (str): URL alvo
            scan_type (str): Tipo de escaneamento realizado
        """
        self.results = scan_results
        self.target_url = target_url
        self.scan_type = scan_type
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    def generate(self):
        """
        Gera o relatório completo.
        
        Returns:
            dict: Relatório formatado
        """
        logger.info("Gerando relatório...")
        
        report = {
            'websp1der_version': '1.0.0',
            'report_generated': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'scan_info': {
                'target_url': self.target_url,
                'scan_type': self.scan_type,
                'start_time': self.results.get('start_time'),
                'end_time': self.results.get('end_time'),
                'duration_seconds': self.results.get('scan_duration')
            },
            'summary': self._generate_summary(),
            'vulnerabilities': self._format_vulnerabilities(),
            'recommendations': self._generate_recommendations(),
            'scan_details': {
                'crawled_urls': self.results.get('crawled_urls', []),
                'forms_analyzed': self.results.get('forms', [])
            }
        }
        
        logger.info("Relatório gerado com sucesso")
        return report
    
    def _generate_summary(self):
        """
        Gera o resumo do escaneamento.
        
        Returns:
            dict: Resumo formatado
        """
        vulnerabilities = self.results.get('vulnerabilities', [])
        
        # Contar por severidade
        severity_count = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'info').lower()
            if severity in severity_count:
                severity_count[severity] += 1
        
        # Contar por tipo
        vuln_types = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', 'unknown')
            if vuln_type in vuln_types:
                vuln_types[vuln_type] += 1
            else:
                vuln_types[vuln_type] = 1
        
        summary = {
            'total_vulnerabilities': len(vulnerabilities),
            'severity_counts': severity_count,
            'vulnerability_types': vuln_types,
            'urls_crawled': len(self.results.get('crawled_urls', [])),
            'forms_analyzed': len(self.results.get('forms', []))
        }
        
        return summary
    
    def _format_vulnerabilities(self):
        """
        Formata as vulnerabilidades para o relatório.
        
        Returns:
            list: Lista de vulnerabilidades formatadas
        """
        formatted_vulns = []
        
        for idx, vuln in enumerate(self.results.get('vulnerabilities', []), 1):
            formatted_vuln = {
                'id': f"WEBSP1DER-{self.timestamp}-{idx:04d}",
                'type': vuln.get('type', 'unknown'),
                'name': vuln.get('name', 'Vulnerabilidade Desconhecida'),
                'severity': vuln.get('severity', 'info'),
                'description': vuln.get('description', ''),
                'location': vuln.get('location', ''),
                'evidence': vuln.get('evidence', ''),
                'cwe_id': vuln.get('cwe_id', ''),
                'remediation': vuln.get('remediation', '')
            }
            
            formatted_vulns.append(formatted_vuln)
        
        # Ordenar por severidade (critical, high, medium, low, info)
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        formatted_vulns.sort(key=lambda x: severity_order.get(x['severity'], 999))
        
        return formatted_vulns
    
    def _generate_recommendations(self):
        """
        Gera recomendações com base nas vulnerabilidades encontradas.
        
        Returns:
            list: Lista de recomendações
        """
        recommendations = []
        vuln_types = set()
        
        for vuln in self.results.get('vulnerabilities', []):
            vuln_types.add(vuln.get('type', ''))
        
        # Recomendações gerais baseadas nos tipos de vulnerabilidades
        if 'xss' in vuln_types:
            recommendations.append({
                'title': 'Mitigação de Cross-Site Scripting (XSS)',
                'description': 'Implemente a validação adequada da entrada do usuário e utilize codificação de saída. '
                              'Considere o uso de Content Security Policy (CSP) para mitigar o impacto de ataques XSS.'
            })
        
        if 'sql_injection' in vuln_types:
            recommendations.append({
                'title': 'Prevenção de Injeção SQL',
                'description': 'Utilize consultas parametrizadas ou prepared statements em vez de concatenação de strings. '
                              'Implemente o princípio do privilégio mínimo para o usuário do banco de dados.'
            })
        
        if 'csrf' in vuln_types:
            recommendations.append({
                'title': 'Proteção contra CSRF',
                'description': 'Implemente tokens anti-CSRF em todos os formulários e verifique-os no servidor. '
                              'Considere o uso de cabeçalhos SameSite para cookies.'
            })
        
        if 'header_security' in vuln_types:
            recommendations.append({
                'title': 'Melhoria nos Cabeçalhos de Segurança',
                'description': 'Implemente cabeçalhos de segurança como Strict-Transport-Security, X-Content-Type-Options, '
                              'X-Frame-Options e Content-Security-Policy para melhorar a postura de segurança do aplicativo.'
            })
        
        # Adicione recomendações gerais
        recommendations.append({
            'title': 'Atualizações Regulares',
            'description': 'Mantenha todos os componentes do sistema, frameworks e bibliotecas atualizados com as versões mais recentes.'
        })
        
        recommendations.append({
            'title': 'Testes de Segurança Contínuos',
            'description': 'Implemente testes de segurança contínuos como parte do processo de desenvolvimento para detectar vulnerabilidades precocemente.'
        })
        
        return recommendations
    
    def save_report(self, output_file, report=None):
        """
        Salva o relatório em um arquivo.
        
        Args:
            output_file (str): Caminho do arquivo de saída
            report (dict, opcional): Relatório para salvar. Se None, gera um novo.
            
        Returns:
            bool: True se o relatório foi salvo com sucesso, False caso contrário
        """
        if report is None:
            report = self.generate()
        
        try:
            # Determinar o formato com base na extensão do arquivo
            file_ext = os.path.splitext(output_file)[1].lower()
            
            if file_ext == '.json':
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(report, f, indent=4, ensure_ascii=False)
            elif file_ext in ['.yml', '.yaml']:
                with open(output_file, 'w', encoding='utf-8') as f:
                    yaml.dump(report, f, default_flow_style=False, allow_unicode=True)
            elif file_ext == '.html':
                self._save_html_report(output_file, report)
            else:
                # Formato padrão JSON
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(report, f, indent=4, ensure_ascii=False)
            
            logger.info(f"Relatório salvo com sucesso em {output_file}")
            return True
            
        except Exception as e:
            logger.error(f"Erro ao salvar relatório: {str(e)}")
            return False
    
    def _save_html_report(self, output_file, report):
        """
        Salva o relatório em formato HTML.
        
        Args:
            output_file (str): Caminho do arquivo de saída
            report (dict): Relatório para salvar
        """
        # Aqui seria implementada a lógica para gerar um relatório HTML bonito
        # Poderia usar um template engine como Jinja2
        # Por simplicidade, vamos apenas criar um HTML básico
        
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebSp1der - Relatório de Segurança</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; color: #333; }}
        h1 {{ color: #2c3e50; }}
        h2 {{ color: #3498db; margin-top: 30px; border-bottom: 1px solid #eee; padding-bottom: 10px; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f8f9fa; }}
        tr:hover {{ background-color: #f1f1f1; }}
        .critical {{ background-color: #ffdddd; }}
        .high {{ background-color: #ffeecc; }}
        .medium {{ background-color: #ffffcc; }}
        .low {{ background-color: #e6ffee; }}
        .info {{ background-color: #e6f2ff; }}
        .summary {{ background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
        .header {{ background-color: #2c3e50; color: white; padding: 20px; margin-bottom: 20px; }}
        .footer {{ margin-top: 50px; text-align: center; color: #7f8c8d; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>WebSp1der - Relatório de Segurança</h1>
        <p>Gerado em: {report['report_generated']}</p>
    </div>
    
    <h2>Informações do Escaneamento</h2>
    <div class="summary">
        <p><strong>URL Alvo:</strong> {report['scan_info']['target_url']}</p>
        <p><strong>Tipo de Escaneamento:</strong> {report['scan_info']['scan_type']}</p>
        <p><strong>Início:</strong> {report['scan_info']['start_time']}</p>
        <p><strong>Término:</strong> {report['scan_info']['end_time']}</p>
        <p><strong>Duração:</strong> {report['scan_info']['duration_seconds']} segundos</p>
    </div>
    
    <h2>Resumo das Vulnerabilidades</h2>
    <div class="summary">
        <p><strong>Total de Vulnerabilidades:</strong> {report['summary']['total_vulnerabilities']}</p>
        <p><strong>Críticas:</strong> {report['summary']['severity_counts']['critical']}</p>
        <p><strong>Altas:</strong> {report['summary']['severity_counts']['high']}</p>
        <p><strong>Médias:</strong> {report['summary']['severity_counts']['medium']}</p>
        <p><strong>Baixas:</strong> {report['summary']['severity_counts']['low']}</p>
        <p><strong>Informativas:</strong> {report['summary']['severity_counts']['info']}</p>
    </div>
    
    <h2>Vulnerabilidades Identificadas</h2>
"""
        
        # Adicionar vulnerabilidades
        if report['vulnerabilities']:
            html_content += """    <table>
        <tr>
            <th>ID</th>
            <th>Nome</th>
            <th>Severidade</th>
            <th>Localização</th>
            <th>Descrição</th>
        </tr>
"""
            
            for vuln in report['vulnerabilities']:
                html_content += f"""        <tr class="{vuln['severity']}">
            <td>{vuln['id']}</td>
            <td>{vuln['name']}</td>
            <td>{vuln['severity'].capitalize()}</td>
            <td>{vuln['location']}</td>
            <td>{vuln['description']}</td>
        </tr>
"""
            
            html_content += "    </table>\n"
        else:
            html_content += "    <p>Nenhuma vulnerabilidade identificada.</p>\n"
        
        # Adicionar recomendações
        html_content += """    <h2>Recomendações</h2>
    <ul>
"""
        
        for rec in report['recommendations']:
            html_content += f"""        <li>
            <strong>{rec['title']}</strong> - {rec['description']}
        </li>
"""
        
        html_content += """    </ul>
    
    <div class="footer">
        <p>Gerado pela ferramenta WebSp1der v1.0.0 - Desenvolvido por mairinkdev</p>
    </div>
</body>
</html>
"""
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
    
    def print_report_summary(self):
        """Imprime um resumo do relatório no console."""
        summary = self._generate_summary()
        
        console.print("\n[bold]Resumo do Escaneamento[/bold]")
        console.print(f"URL: [cyan]{self.target_url}[/cyan]")
        console.print(f"Total de Vulnerabilidades: [bold red]{summary['total_vulnerabilities']}[/bold red]")
        
        table = Table(title="Vulnerabilidades por Severidade")
        table.add_column("Severidade", style="cyan")
        table.add_column("Quantidade", style="magenta")
        
        table.add_row("Crítica", str(summary['severity_counts']['critical']))
        table.add_row("Alta", str(summary['severity_counts']['high']))
        table.add_row("Média", str(summary['severity_counts']['medium']))
        table.add_row("Baixa", str(summary['severity_counts']['low']))
        table.add_row("Informativa", str(summary['severity_counts']['info']))
        
        console.print(table)
        
        if summary['vulnerability_types']:
            console.print("\n[bold]Tipos de Vulnerabilidades Encontradas:[/bold]")
            for vuln_type, count in summary['vulnerability_types'].items():
                console.print(f"- {vuln_type}: {count}")
        
        console.print(f"\nURLs Analisadas: [green]{summary['urls_crawled']}[/green]")
        console.print(f"Formulários Analisados: [green]{summary['forms_analyzed']}[/green]") 