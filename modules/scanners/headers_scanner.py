#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WebSp1der - Scanner de Cabeçalhos de Segurança
Desenvolvido por: mairinkdev (https://github.com/mairinkdev)
"""

import logging
import requests
from urllib.parse import urlparse
from ..utils import Utils

logger = logging.getLogger('websp1der.scanners.headers')

class HeadersScanner:
    """Scanner para verificação de cabeçalhos de segurança."""
    
    def __init__(self, url=None, session=None):
        """
        Inicializa o scanner de cabeçalhos.
        
        Args:
            url (str, opcional): URL alvo para escaneamento
            session (requests.Session, opcional): Sessão de requests para manter cookies/estado
        """
        self.name = "Security Headers Scanner"
        self.description = "Scanner para verificação de cabeçalhos de segurança HTTP"
        self.target_url = url
        self.session = session or requests.Session()
        
        # Cabeçalhos de segurança importantes
        self.security_headers = {
            'strict-transport-security': {
                'description': 'HTTP Strict Transport Security (HSTS)',
                'importance': 'high',
                'recommendation': 'Implementar HSTS com um tempo máximo de pelo menos 6 meses'
            },
            'content-security-policy': {
                'description': 'Content Security Policy (CSP)',
                'importance': 'high',
                'recommendation': 'Implementar CSP para controlar recursos que podem ser carregados'
            },
            'x-content-type-options': {
                'description': 'X-Content-Type-Options',
                'importance': 'medium',
                'recommendation': 'Configurar X-Content-Type-Options: nosniff'
            },
            'x-frame-options': {
                'description': 'X-Frame-Options',
                'importance': 'high',
                'recommendation': 'Configurar X-Frame-Options: DENY ou SAMEORIGIN'
            },
            'x-xss-protection': {
                'description': 'X-XSS-Protection',
                'importance': 'medium',
                'recommendation': 'Configurar X-XSS-Protection: 1; mode=block'
            },
            'referrer-policy': {
                'description': 'Referrer-Policy',
                'importance': 'medium',
                'recommendation': 'Configurar Referrer-Policy para limitar informações enviadas a outros sites'
            },
            'permissions-policy': {
                'description': 'Permissions-Policy (anteriormente Feature-Policy)',
                'importance': 'medium',
                'recommendation': 'Configurar Permissions-Policy para controlar quais recursos podem ser usados'
            },
            'cross-origin-embedder-policy': {
                'description': 'Cross-Origin Embedder Policy (COEP)',
                'importance': 'low',
                'recommendation': 'Configurar COEP para recursos de cross-origin'
            },
            'cross-origin-opener-policy': {
                'description': 'Cross-Origin Opener Policy (COOP)',
                'importance': 'low',
                'recommendation': 'Configurar COOP para proteger contra ataques de cross-origin'
            },
            'cross-origin-resource-policy': {
                'description': 'Cross-Origin Resource Policy (CORP)',
                'importance': 'low',
                'recommendation': 'Configurar CORP para controlar como recursos podem ser carregados'
            }
        }
        
        # Cabeçalhos que podem revelar informações sensíveis
        self.information_headers = {
            'server': {
                'description': 'Server',
                'issue': 'Revela informações sobre o servidor utilizado',
                'severity': 'info'
            },
            'x-powered-by': {
                'description': 'X-Powered-By',
                'issue': 'Revela informações sobre a tecnologia utilizada',
                'severity': 'info'
            },
            'x-aspnet-version': {
                'description': 'X-AspNet-Version',
                'issue': 'Revela a versão do ASP.NET utilizada',
                'severity': 'info'
            }
        }
        
        # Configurações CORS inseguras
        self.insecure_cors = [
            {'header': 'access-control-allow-origin', 'value': '*', 'severity': 'medium'},
            {'header': 'access-control-allow-credentials', 'value': 'true', 'severity': 'high'}
        ]
    
    def check_headers(self, url, headers=None, proxies=None):
        """
        Verifica cabeçalhos de segurança em uma URL.
        
        Args:
            url (str): URL para verificar
            headers (dict, opcional): Cabeçalhos HTTP personalizados
            proxies (dict, opcional): Configuração de proxy
            
        Returns:
            list: Lista de vulnerabilidades encontradas
        """
        vulnerabilities = []
        
        try:
            # Fazer requisição para obter cabeçalhos
            response = self.session.get(
                url,
                headers=headers,
                proxies=proxies,
                timeout=10,
                verify=False,  # Desabilitar verificação SSL para testes
                allow_redirects=True
            )
            
            # Extrair cabeçalhos (converter para minúsculas para comparação)
            response_headers = {k.lower(): v for k, v in response.headers.items()}
            
            # Verificar cabeçalhos de segurança ausentes
            missing_headers = []
            
            for header_name, header_info in self.security_headers.items():
                if header_name not in response_headers:
                    missing_headers.append({
                        'name': header_name,
                        'description': header_info['description'],
                        'recommended': header_info['recommendation'],
                        'severity': 'high'
                    })
            
            # Se há cabeçalhos ausentes, reportar vulnerabilidade
            if missing_headers:
                header_descriptions = ', '.join([h['name'] for h in missing_headers])
                
                vulnerability = {
                    'type': 'header_security',
                    'name': 'Cabeçalhos de Segurança Ausentes',
                    'severity': 'high',
                    'url': url,
                    'description': 'A resposta não inclui cabeçalhos de segurança importantes.',
                    'details': f"Cabeçalhos ausentes: {header_descriptions}",
                    'recommendation': """
                    Configurar os seguintes cabeçalhos de segurança no servidor web:
                    
                    {}
                    """.format('\n'.join([f"- {h['name']}: {h['recommended']}" for h in missing_headers]))
                }
                vulnerabilities.append(vulnerability)
            
            # Verificar informações de servidor expostas
            server_headers = []
            expose_headers = ['server', 'x-powered-by', 'x-aspnet-version', 'x-asp-version']
            
            for header in expose_headers:
                if header in response_headers:
                    server_headers.append(f"{header}: {response_headers[header]}")
            
            if server_headers:
                vulnerability = {
                    'type': 'info',
                    'name': 'Informações de Servidor Expostas',
                    'severity': 'low',
                    'url': url,
                    'description': 'A resposta expõe informações sobre a tecnologia do servidor.',
                    'details': f"Cabeçalhos expostos: {', '.join(server_headers)}",
                    'recommendation': """
                    Remover ou modificar os seguintes cabeçalhos para esconder informações sobre tecnologias do servidor:
                    
                    {}
                    """.format('\n'.join(server_headers))
                }
                vulnerabilities.append(vulnerability)
                
        except requests.RequestException as e:
            logger.error(f"Erro ao verificar cabeçalhos em {url}: {str(e)}")
        
        return vulnerabilities
    
    def scan(self):
        """
        Executa o escaneamento de cabeçalhos de segurança.
        
        Returns:
            list: Lista de vulnerabilidades encontradas
        """
        if not self.target_url:
            logger.error("URL alvo não especificada para Headers Scanner")
            return []
            
        vulnerabilities = []
        
        # Verificar cabeçalhos da URL principal
        headers_vulns = self.check_headers(self.target_url)
        vulnerabilities.extend(headers_vulns)
        
        return vulnerabilities 