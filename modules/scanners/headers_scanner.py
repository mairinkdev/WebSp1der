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
    
    def __init__(self):
        """Inicializa o scanner de cabeçalhos."""
        self.name = "Security Headers Scanner"
        self.description = "Scanner para verificação de cabeçalhos de segurança HTTP"
        
        # Cabeçalhos de segurança importantes
        self.security_headers = {
            'strict-transport-security': {
                'description': 'HTTP Strict Transport Security (HSTS)',
                'recommended': 'max-age=31536000; includeSubDomains',
                'severity': 'medium'
            },
            'content-security-policy': {
                'description': 'Content Security Policy (CSP)',
                'recommended': "default-src 'self'",
                'severity': 'medium'
            },
            'x-content-type-options': {
                'description': 'X-Content-Type-Options',
                'recommended': 'nosniff',
                'severity': 'low'
            },
            'x-frame-options': {
                'description': 'X-Frame-Options',
                'recommended': 'DENY ou SAMEORIGIN',
                'severity': 'medium'
            },
            'x-xss-protection': {
                'description': 'X-XSS-Protection',
                'recommended': '1; mode=block',
                'severity': 'low'
            },
            'referrer-policy': {
                'description': 'Referrer-Policy',
                'recommended': 'strict-origin-when-cross-origin',
                'severity': 'low'
            },
            'permissions-policy': {
                'description': 'Permissions-Policy',
                'recommended': 'camera=(), microphone=(), geolocation=()',
                'severity': 'low'
            },
            'cache-control': {
                'description': 'Cache-Control',
                'recommended': 'no-store, max-age=0',
                'severity': 'low'
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
        Verifica os cabeçalhos de segurança de uma URL.
        
        Args:
            url (str): URL para verificar
            headers (dict, opcional): Cabeçalhos da requisição
            proxies (dict, opcional): Configuração de proxy
            
        Returns:
            list: Lista de problemas encontrados
        """
        vulnerabilities = []
        
        try:
            logger.debug(f"Verificando cabeçalhos de segurança para: {url}")
            
            # Fazer requisição para obter os cabeçalhos
            response = requests.get(
                url,
                headers=headers,
                proxies=proxies,
                timeout=10,
                verify=False,  # Desabilitar verificação SSL para testes
                allow_redirects=True
            )
            
            response_headers = {k.lower(): v for k, v in response.headers.items()}
            
            # Verificar cabeçalhos de segurança ausentes
            missing_headers = []
            for header_name, header_info in self.security_headers.items():
                if header_name not in response_headers:
                    missing_headers.append({
                        'name': header_name,
                        'description': header_info['description'],
                        'recommended': header_info['recommended'],
                        'severity': header_info['severity']
                    })
            
            if missing_headers:
                vulnerability = {
                    'type': 'header_security',
                    'name': 'Cabeçalhos de Segurança Ausentes',
                    'severity': 'medium',
                    'location': url,
                    'description': 'A resposta não inclui cabeçalhos de segurança importantes.',
                    'evidence': f"Cabeçalhos ausentes: {', '.join([h['name'] for h in missing_headers])}",
                    'cwe_id': 'CWE-693',
                    'remediation': """
                    Configure o servidor web para incluir os seguintes cabeçalhos de segurança:
                    
                    """ + '\n'.join([f"- {h['name']}: {h['recommended']} ({h['description']})" for h in missing_headers])
                }
                vulnerabilities.append(vulnerability)
            
            # Verificar cabeçalhos que revelam informações
            info_headers = []
            for header_name, header_info in self.information_headers.items():
                if header_name in response_headers:
                    info_headers.append({
                        'name': header_name,
                        'value': response_headers[header_name],
                        'issue': header_info['issue']
                    })
            
            if info_headers:
                vulnerability = {
                    'type': 'information_disclosure',
                    'name': 'Divulgação de Informações em Cabeçalhos',
                    'severity': 'low',
                    'location': url,
                    'description': 'A resposta inclui cabeçalhos que revelam informações sobre o sistema.',
                    'evidence': '\n'.join([f"{h['name']}: {h['value']} - {h['issue']}" for h in info_headers]),
                    'cwe_id': 'CWE-200',
                    'remediation': """
                    Configure o servidor web para remover ou substituir os cabeçalhos que revelam informações sensíveis:
                    
                    """ + '\n'.join([f"- {h['name']}: {h['issue']}" for h in info_headers])
                }
                vulnerabilities.append(vulnerability)
            
            # Verificar configurações CORS
            cors_issues = []
            for cors_check in self.insecure_cors:
                header_name = cors_check['header']
                insecure_value = cors_check['value']
                
                if header_name in response_headers and response_headers[header_name] == insecure_value:
                    cors_issues.append({
                        'name': header_name,
                        'value': response_headers[header_name],
                        'severity': cors_check['severity']
                    })
            
            if cors_issues:
                vulnerability = {
                    'type': 'cors_misconfiguration',
                    'name': 'Configuração CORS Insegura',
                    'severity': 'medium',
                    'location': url,
                    'description': 'A configuração CORS permite acesso de origens não confiáveis.',
                    'evidence': '\n'.join([f"{h['name']}: {h['value']}" for h in cors_issues]),
                    'cwe_id': 'CWE-942',
                    'remediation': """
                    Configure adequadamente os cabeçalhos CORS para restringir o acesso a origens confiáveis:
                    
                    1. Não use 'Access-Control-Allow-Origin: *' em conjunto com 'Access-Control-Allow-Credentials: true'.
                    2. Especifique origens confiáveis explicitamente em vez de usar o curinga '*'.
                    3. Limite os métodos HTTP permitidos com 'Access-Control-Allow-Methods'.
                    4. Limite os cabeçalhos permitidos com 'Access-Control-Allow-Headers'.
                    """
                }
                vulnerabilities.append(vulnerability)
            
            # Verificar se o site usa HTTPS
            parsed_url = urlparse(url)
            if parsed_url.scheme != 'https':
                vulnerability = {
                    'type': 'insecure_protocol',
                    'name': 'Uso de Protocolo Inseguro (HTTP)',
                    'severity': 'high',
                    'location': url,
                    'description': 'O site está usando HTTP em vez de HTTPS, o que não protege a privacidade e integridade dos dados.',
                    'evidence': f"URL: {url}",
                    'cwe_id': 'CWE-319',
                    'remediation': """
                    1. Implemente HTTPS em todo o site usando certificados SSL/TLS válidos.
                    2. Configure o redirecionamento automático de HTTP para HTTPS.
                    3. Implemente o cabeçalho HSTS para forçar conexões HTTPS.
                    4. Use preload HSTS para proteção adicional.
                    """
                }
                vulnerabilities.append(vulnerability)
            
            # Verificar cookie sem flags de segurança
            insecure_cookies = []
            for cookie in response.cookies:
                issues = []
                
                if not cookie.secure:
                    issues.append("Ausência da flag 'Secure'")
                
                if not cookie.has_nonstandard_attr('HttpOnly'):
                    issues.append("Ausência da flag 'HttpOnly'")
                
                if not cookie.has_nonstandard_attr('SameSite'):
                    issues.append("Ausência da flag 'SameSite'")
                
                if issues:
                    insecure_cookies.append({
                        'name': cookie.name,
                        'issues': issues
                    })
            
            if insecure_cookies:
                vulnerability = {
                    'type': 'insecure_cookie',
                    'name': 'Cookies com Flags de Segurança Ausentes',
                    'severity': 'medium',
                    'location': url,
                    'description': 'Os cookies definidos não incluem flags de segurança importantes.',
                    'evidence': '\n'.join([f"Cookie: {c['name']} - Problemas: {', '.join(c['issues'])}" for c in insecure_cookies]),
                    'cwe_id': 'CWE-614',
                    'remediation': """
                    Configure os cookies com as seguintes flags de segurança:
                    
                    1. Secure: Garante que o cookie seja transmitido apenas em conexões HTTPS.
                    2. HttpOnly: Impede o acesso ao cookie via JavaScript, reduzindo o risco de XSS.
                    3. SameSite=Lax ou SameSite=Strict: Protege contra ataques CSRF limitando o envio de cookies em requisições cross-site.
                    """
                }
                vulnerabilities.append(vulnerability)
            
        except requests.RequestException as e:
            logger.error(f"Erro ao verificar cabeçalhos de {url}: {str(e)}")
        
        return vulnerabilities
    
    def scan(self, urls, forms, proxies=None, headers=None):
        """
        Executa o escaneamento de cabeçalhos de segurança.
        
        Args:
            urls (list): Lista de URLs para analisar
            forms (list): Lista de formulários para analisar (não usada por este scanner)
            proxies (dict, opcional): Configuração de proxy
            headers (dict, opcional): Cabeçalhos HTTP
            
        Returns:
            list: Lista de vulnerabilidades encontradas
        """
        vulnerabilities = []
        
        logger.info("Iniciando escaneamento de cabeçalhos de segurança...")
        
        # Analisar URLs únicas para verificar cabeçalhos
        unique_base_urls = set()
        
        for url in urls:
            parsed_url = urlparse(url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            if base_url not in unique_base_urls:
                unique_base_urls.add(base_url)
                
                # Verificar cabeçalhos na URL base
                header_vulns = self.check_headers(base_url, headers, proxies)
                vulnerabilities.extend(header_vulns)
        
        logger.info(f"Escaneamento de cabeçalhos concluído. Encontradas {len(vulnerabilities)} vulnerabilidades.")
        
        return vulnerabilities 