#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WebSp1der - Scanner de Portas
Desenvolvido por: mairinkdev (https://github.com/mairinkdev)
"""

import logging
import socket
import concurrent.futures
from urllib.parse import urlparse
from ..utils import Utils

logger = logging.getLogger('websp1der.scanners.port')

class PortScanner:
    """Scanner para detecção de portas abertas."""
    
    def __init__(self):
        """Inicializa o scanner de portas."""
        self.name = "Port Scanner"
        self.description = "Scanner para detecção de portas abertas em hosts"
        
        # Portas comuns e seus serviços associados
        self.common_ports = {
            21: {'service': 'FTP', 'severity': 'medium'},
            22: {'service': 'SSH', 'severity': 'low'},
            23: {'service': 'Telnet', 'severity': 'high'},
            25: {'service': 'SMTP', 'severity': 'medium'},
            53: {'service': 'DNS', 'severity': 'low'},
            80: {'service': 'HTTP', 'severity': 'low'},
            110: {'service': 'POP3', 'severity': 'medium'},
            139: {'service': 'NetBIOS', 'severity': 'high'},
            143: {'service': 'IMAP', 'severity': 'medium'},
            443: {'service': 'HTTPS', 'severity': 'low'},
            445: {'service': 'SMB', 'severity': 'high'},
            465: {'service': 'SMTPS', 'severity': 'medium'},
            587: {'service': 'SMTP Submission', 'severity': 'medium'},
            993: {'service': 'IMAPS', 'severity': 'medium'},
            995: {'service': 'POP3S', 'severity': 'medium'},
            1433: {'service': 'MSSQL', 'severity': 'high'},
            1521: {'service': 'Oracle', 'severity': 'high'},
            3306: {'service': 'MySQL', 'severity': 'high'},
            3389: {'service': 'RDP', 'severity': 'high'},
            5432: {'service': 'PostgreSQL', 'severity': 'high'},
            5900: {'service': 'VNC', 'severity': 'high'},
            5985: {'service': 'WinRM', 'severity': 'high'},
            6379: {'service': 'Redis', 'severity': 'high'},
            8080: {'service': 'HTTP-Proxy', 'severity': 'medium'},
            8443: {'service': 'HTTPS-Alt', 'severity': 'medium'},
            27017: {'service': 'MongoDB', 'severity': 'high'}
        }
        
        # Serviços críticos que não devem estar acessíveis publicamente
        self.critical_services = [23, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 5985, 6379, 27017]
        
        # Configuração padrão
        self.timeout = 1  # Timeout em segundos para verificação de porta
        self.max_workers = 50  # Número máximo de workers para execução paralela
    
    def check_port(self, host, port):
        """
        Verifica se uma porta está aberta em um host.
        
        Args:
            host (str): Endereço do host
            port (int): Número da porta
            
        Returns:
            bool: True se a porta estiver aberta, False caso contrário
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except (socket.error, socket.gaierror, OverflowError, TypeError):
            return False
    
    def scan_ports(self, host, ports=None):
        """
        Escaneia um conjunto de portas em um host.
        
        Args:
            host (str): Endereço do host
            ports (list, opcional): Lista de portas para verificar. Se None, usa as portas comuns.
            
        Returns:
            list: Lista de portas abertas e suas informações
        """
        if ports is None:
            ports = list(self.common_ports.keys())
        
        open_ports = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_port = {executor.submit(self.check_port, host, port): port for port in ports}
            
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    is_open = future.result()
                    if is_open:
                        port_info = self.common_ports.get(port, {'service': 'Unknown', 'severity': 'info'})
                        open_ports.append({
                            'port': port,
                            'service': port_info['service'],
                            'severity': port_info['severity']
                        })
                except Exception as e:
                    logger.error(f"Erro ao verificar porta {port}: {str(e)}")
        
        return open_ports
    
    def get_host_from_url(self, url):
        """
        Extrai o host de uma URL.
        
        Args:
            url (str): URL para extrair o host
            
        Returns:
            str: Host extraído
        """
        try:
            parsed_url = urlparse(url)
            return parsed_url.netloc.split(':')[0]
        except Exception:
            return None
    
    def scan(self, urls, forms, proxies=None, headers=None):
        """
        Executa o escaneamento de portas em hosts extraídos das URLs.
        
        Args:
            urls (list): Lista de URLs para analisar
            forms (list): Lista de formulários (não utilizado por este scanner)
            proxies (dict, opcional): Configuração de proxy (não utilizado por este scanner)
            headers (dict, opcional): Cabeçalhos HTTP (não utilizado por este scanner)
            
        Returns:
            list: Lista de vulnerabilidades encontradas
        """
        vulnerabilities = []
        
        logger.info("Iniciando escaneamento de portas...")
        
        # Extrair hosts únicos das URLs
        hosts = set()
        for url in urls:
            host = self.get_host_from_url(url)
            if host:
                hosts.add(host)
        
        # Verificar portas em cada host
        for host in hosts:
            logger.debug(f"Escaneando portas para o host: {host}")
            
            # Resolver o endereço IP do host
            try:
                ip = socket.gethostbyname(host)
                logger.debug(f"Host {host} resolvido para IP: {ip}")
                
                # Escanear portas
                open_ports = self.scan_ports(ip)
                
                if open_ports:
                    # Agrupar vulnerabilidades por severidade
                    critical_ports = []
                    high_ports = []
                    medium_ports = []
                    low_ports = []
                    
                    for port_info in open_ports:
                        port = port_info['port']
                        
                        # Classificar portas com base na severidade
                        if port in self.critical_services:
                            critical_ports.append(port_info)
                        elif port_info['severity'] == 'high':
                            high_ports.append(port_info)
                        elif port_info['severity'] == 'medium':
                            medium_ports.append(port_info)
                        else:
                            low_ports.append(port_info)
                    
                    # Relatar portas críticas
                    if critical_ports:
                        vulnerability = {
                            'type': 'open_critical_port',
                            'name': 'Serviços Críticos Expostos',
                            'severity': 'critical',
                            'location': f"Host: {host} ({ip})",
                            'description': 'Serviços críticos estão publicamente acessíveis, o que pode levar a acesso não autorizado.',
                            'evidence': '\n'.join([f"Porta {p['port']} ({p['service']})" for p in critical_ports]),
                            'cwe_id': 'CWE-16',
                            'remediation': """
                            1. Restrinja o acesso a serviços críticos através de firewalls.
                            2. Use VPNs ou tunelamento SSH para acesso a serviços internos.
                            3. Considere mover serviços para redes isoladas e protegidas.
                            4. Implemente autenticação forte e criptografia para todos os serviços.
                            5. Monitore e audite regularmente o acesso a esses serviços.
                            """
                        }
                        vulnerabilities.append(vulnerability)
                    
                    # Relatar portas de alta severidade
                    if high_ports:
                        vulnerability = {
                            'type': 'open_high_risk_port',
                            'name': 'Serviços de Alto Risco Expostos',
                            'severity': 'high',
                            'location': f"Host: {host} ({ip})",
                            'description': 'Serviços de alto risco estão publicamente acessíveis.',
                            'evidence': '\n'.join([f"Porta {p['port']} ({p['service']})" for p in high_ports]),
                            'cwe_id': 'CWE-16',
                            'remediation': """
                            1. Restrinja o acesso a esses serviços através de firewalls.
                            2. Implemente autenticação forte.
                            3. Mantenha os serviços atualizados com as últimas patches de segurança.
                            """
                        }
                        vulnerabilities.append(vulnerability)
                    
                    # Relatar todas as portas abertas (informativo)
                    all_ports = critical_ports + high_ports + medium_ports + low_ports
                    vulnerability = {
                        'type': 'open_ports',
                        'name': 'Portas Abertas Detectadas',
                        'severity': 'info',
                        'location': f"Host: {host} ({ip})",
                        'description': 'As seguintes portas estão abertas no host.',
                        'evidence': '\n'.join([f"Porta {p['port']} ({p['service']})" for p in all_ports]),
                        'cwe_id': 'CWE-16',
                        'remediation': """
                        1. Revise regularmente as portas abertas e desabilite serviços desnecessários.
                        2. Mantenha todos os serviços atualizados com as últimas patches de segurança.
                        3. Configure corretamente as regras de firewall para permitir apenas o tráfego necessário.
                        """
                    }
                    vulnerabilities.append(vulnerability)
                
            except socket.gaierror:
                logger.error(f"Não foi possível resolver o host: {host}")
            except Exception as e:
                logger.error(f"Erro ao escanear portas para {host}: {str(e)}")
        
        logger.info(f"Escaneamento de portas concluído. Encontradas {len(vulnerabilities)} vulnerabilidades.")
        
        return vulnerabilities 