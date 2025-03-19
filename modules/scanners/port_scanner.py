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
    
    def __init__(self, url=None, threads=10, timeout=3):
        """
        Inicializa o scanner de portas.
        
        Args:
            url (str, opcional): URL alvo para escaneamento
            threads (int, opcional): Número de threads para escaneamento paralelo
            timeout (int, opcional): Timeout para conexões em segundos
        """
        self.name = "Port Scanner"
        self.description = "Scanner para detecção de portas abertas em hosts"
        self.target_url = url
        self.threads = threads
        self.timeout = timeout
        
        # Portas comuns e seus serviços associados
        self.common_ports = {
            21: {'service': 'FTP', 'severity': 'medium'},
            22: {'service': 'SSH', 'severity': 'medium'},
            23: {'service': 'Telnet', 'severity': 'high'},
            25: {'service': 'SMTP', 'severity': 'medium'},
            53: {'service': 'DNS', 'severity': 'low'},
            80: {'service': 'HTTP', 'severity': 'low'},
            110: {'service': 'POP3', 'severity': 'medium'},
            111: {'service': 'RPC', 'severity': 'medium'},
            135: {'service': 'RPC/DCOM', 'severity': 'high'},
            139: {'service': 'NetBIOS', 'severity': 'high'},
            143: {'service': 'IMAP', 'severity': 'medium'},
            443: {'service': 'HTTPS', 'severity': 'low'},
            445: {'service': 'SMB', 'severity': 'high'},
            993: {'service': 'IMAPS', 'severity': 'low'},
            995: {'service': 'POP3S', 'severity': 'low'},
            1433: {'service': 'MSSQL', 'severity': 'high'},
            1521: {'service': 'Oracle', 'severity': 'high'},
            3306: {'service': 'MySQL', 'severity': 'high'},
            3389: {'service': 'RDP', 'severity': 'high'},
            5432: {'service': 'PostgreSQL', 'severity': 'high'},
            5900: {'service': 'VNC', 'severity': 'high'},
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
        Verifica se uma porta específica está aberta.
        
        Args:
            host (str): Host para verificar
            port (int): Porta para verificar
            
        Returns:
            tuple: (porta, status, banner)
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            
            if result == 0:
                # Tenta obter o banner
                try:
                    sock.send(b'Hello\r\n')
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                except:
                    banner = ""
                    
                sock.close()
                return (port, True, banner)
            
            sock.close()
            return (port, False, "")
            
        except:
            return (port, False, "")
    
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
                    is_open, banner = future.result()
                    if is_open:
                        port_info = self.common_ports.get(port, {'service': 'Unknown', 'severity': 'info'})
                        open_ports.append({
                            'port': port,
                            'service': port_info['service'],
                            'severity': port_info['severity'],
                            'banner': banner
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
    
    def scan(self):
        """
        Executa o escaneamento de portas.
        
        Returns:
            list: Lista de vulnerabilidades encontradas
        """
        if not self.target_url:
            logger.error("URL alvo não especificada para Port Scanner")
            return []
            
        vulnerabilities = []
        
        # Extrair o host da URL alvo
        host = self.get_host_from_url(self.target_url)
        
        if not host:
            return vulnerabilities
            
        # Escanear portas comuns
        open_ports = self.scan_ports(host)
        
        # Criar relatório para cada porta aberta
        for port_info in open_ports:
            port = port_info['port']
            service = port_info['service']
            banner = port_info['banner']
            severity = port_info['severity']
            
            vulnerability = {
                'type': 'open_port',
                'name': f'Porta {port} Aberta ({service})',
                'url': self.target_url,
                'severity': severity,
                'description': f"O host {host} tem a porta {port} ({service}) aberta.",
                'details': f"Banner: {banner}" if banner else "Nenhum banner detectado",
                'recommendation': """
                1. Fechar portas desnecessárias ou restringi-las com firewall.
                2. Usar VPN ou SSH para acesso a serviços internos.
                3. Implementar autenticação forte para serviços expostos.
                4. Considerar o uso de filtragem de IP para limitar o acesso.
                """
            }
            
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities 