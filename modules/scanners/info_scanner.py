#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WebSp1der - Scanner de Informações
Desenvolvido por: mairinkdev (https://github.com/mairinkdev)
"""

import logging
import re
import requests
import socket
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from ..utils import Utils

logger = logging.getLogger('websp1der.scanners.info')

class InfoScanner:
    """Scanner para coleta de informações sobre o alvo."""
    
    def __init__(self, url=None, session=None):
        """
        Inicializa o scanner de informações.
        
        Args:
            url (str, opcional): URL alvo para escaneamento
            session (requests.Session, opcional): Sessão de requests para manter cookies/estado
        """
        self.name = "Information Gathering Scanner"
        self.description = "Scanner para coleta de informações sobre o alvo"
        self.target_url = url
        self.session = session or requests.Session()
        
        # Padrões para detecção de tecnologias
        self.tech_patterns = {
            'wordpress': {
                'patterns': [
                    r'wp-content',
                    r'wp-includes',
                    r'wp-json',
                    r'<meta name="generator" content="WordPress'
                ],
                'type': 'CMS'
            },
            'joomla': {
                'patterns': [
                    r'/components/',
                    r'/modules/',
                    r'<meta name="generator" content="Joomla!'
                ],
                'type': 'CMS'
            },
            'drupal': {
                'patterns': [
                    r'Drupal.settings',
                    r'/sites/default/',
                    r'<meta name="Generator" content="Drupal'
                ],
                'type': 'CMS'
            },
            'laravel': {
                'patterns': [
                    r'laravel_session',
                    r'XSRF-TOKEN',
                    r'"Laravel"'
                ],
                'type': 'Framework'
            },
            'django': {
                'patterns': [
                    r'csrfmiddlewaretoken',
                    r'django',
                    r'__django__'
                ],
                'type': 'Framework'
            },
            'angular': {
                'patterns': [
                    r'ng-app',
                    r'angular.js',
                    r'angular.min.js'
                ],
                'type': 'Frontend'
            },
            'react': {
                'patterns': [
                    r'react.js',
                    r'react.min.js',
                    r'react-dom'
                ],
                'type': 'Frontend'
            },
            'vue': {
                'patterns': [
                    r'vue.js',
                    r'vue.min.js',
                    r'v-bind',
                    r'v-for'
                ],
                'type': 'Frontend'
            },
            'jquery': {
                'patterns': [
                    r'jquery.js',
                    r'jquery.min.js',
                    r'jquery-'
                ],
                'type': 'Library'
            },
            'bootstrap': {
                'patterns': [
                    r'bootstrap.css',
                    r'bootstrap.min.css',
                    r'bootstrap.js',
                    r'bootstrap.min.js'
                ],
                'type': 'Framework'
            },
            'php': {
                'patterns': [
                    r'\.php',
                    r'X-Powered-By: PHP'
                ],
                'type': 'Language'
            },
            'asp.net': {
                'patterns': [
                    r'\.aspx',
                    r'__VIEWSTATE',
                    r'X-AspNet-Version'
                ],
                'type': 'Framework'
            },
            'nginx': {
                'patterns': [
                    r'Server: nginx'
                ],
                'type': 'Server'
            },
            'apache': {
                'patterns': [
                    r'Server: Apache'
                ],
                'type': 'Server'
            },
            'iis': {
                'patterns': [
                    r'Server: Microsoft-IIS'
                ],
                'type': 'Server'
            }
        }
        
        # Configurações padrão
        self.timeout = 10
    
    def extract_html_comments(self, content):
        """
        Extrai comentários HTML de uma página.
        
        Args:
            content (str): Conteúdo HTML
            
        Returns:
            list: Lista de comentários encontrados
        """
        comments = []
        comment_pattern = re.compile(r'<!--(.*?)-->', re.DOTALL)
        
        matches = comment_pattern.finditer(content)
        for match in matches:
            comment = match.group(1).strip()
            if comment and len(comment) > 3:  # Ignorar comentários vazios ou muito curtos
                comments.append(comment)
        
        return comments
    
    def detect_technologies(self, url, content, headers):
        """
        Detecta tecnologias utilizadas pelo site.
        
        Args:
            url (str): URL analisada
            content (str): Conteúdo HTML
            headers (dict): Cabeçalhos HTTP
            
        Returns:
            dict: Tecnologias detectadas agrupadas por tipo
        """
        technologies = {}
        
        for tech_name, tech_info in self.tech_patterns.items():
            tech_type = tech_info['type']
            
            for pattern in tech_info['patterns']:
                # Verificar no conteúdo HTML
                if re.search(pattern, content, re.IGNORECASE):
                    if tech_type not in technologies:
                        technologies[tech_type] = []
                    if tech_name not in technologies[tech_type]:
                        technologies[tech_type].append(tech_name)
                    break
                
                # Verificar nos cabeçalhos
                for header_name, header_value in headers.items():
                    if re.search(pattern, f"{header_name}: {header_value}", re.IGNORECASE):
                        if tech_type not in technologies:
                            technologies[tech_type] = []
                        if tech_name not in technologies[tech_type]:
                            technologies[tech_type].append(tech_name)
                        break
        
        return technologies
    
    def extract_emails(self, content):
        """
        Extrai endereços de e-mail do conteúdo HTML.
        
        Args:
            content (str): Conteúdo HTML
            
        Returns:
            list: Lista de endereços de e-mail encontrados
        """
        email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
        return list(set(email_pattern.findall(content)))
    
    def extract_metadata(self, content):
        """
        Extrai metadados da página HTML.
        
        Args:
            content (str): Conteúdo HTML
            
        Returns:
            dict: Metadados extraídos
        """
        metadata = {
            'title': '',
            'description': '',
            'keywords': '',
            'author': '',
            'generator': '',
            'robots': '',
            'other': {}
        }
        
        try:
            soup = BeautifulSoup(content, 'html.parser')
            
            # Extrair título
            title_tag = soup.find('title')
            if title_tag:
                metadata['title'] = title_tag.string.strip() if title_tag.string else ''
            
            # Extrair metadados
            meta_tags = soup.find_all('meta')
            for tag in meta_tags:
                name = tag.get('name', '').lower()
                property = tag.get('property', '').lower()
                content = tag.get('content', '')
                
                if name == 'description' or property == 'og:description':
                    metadata['description'] = content
                elif name == 'keywords':
                    metadata['keywords'] = content
                elif name == 'author':
                    metadata['author'] = content
                elif name == 'generator':
                    metadata['generator'] = content
                elif name == 'robots':
                    metadata['robots'] = content
                elif name or property:
                    key = name or property
                    metadata['other'][key] = content
        except Exception as e:
            logger.error(f"Erro ao extrair metadados: {str(e)}")
        
        return metadata
    
    def collect_info(self, url, proxies=None, headers=None):
        """
        Coleta informações detalhadas sobre uma URL.
        
        Args:
            url (str): URL para analisar
            proxies (dict, opcional): Configuração de proxy
            headers (dict, opcional): Cabeçalhos HTTP
            
        Returns:
            dict: Informações coletadas
        """
        info = {
            'url': url,
            'domain': urlparse(url).netloc,
            'technologies': [],
            'headers': {},
            'dns_info': {},
            'comments': [],
            'emails': [],
            'metadata': {}
        }
        
        try:
            # Fazer requisição para obter a página
            response = self.session.get(
                url, 
                headers=headers,
                proxies=proxies,
                timeout=10,
                verify=False  # Desabilitar verificação SSL para testes
            )
            
            # Armazenar cabeçalhos da resposta
            info['headers'] = dict(response.headers)
            
            # Extrair tecnologias da resposta
            if response.status_code == 200:
                # Detectar tecnologias do conteúdo HTML e cabeçalhos
                techs = self.detect_technologies(url, response.text, response.headers)
                info['technologies'] = techs
                
                # Extrair comentários HTML
                comments = self.extract_html_comments(response.text)
                info['comments'] = comments
                
                # Extrair endereços de e-mail
                emails = self.extract_emails(response.text)
                info['emails'] = emails
                
                # Extrair metadados
                metadata = self.extract_metadata(response.text)
                info['metadata'] = metadata
            
            # Obter informações de DNS
            try:
                domain = urlparse(url).netloc
                ip = socket.gethostbyname(domain)
                info['dns_info'] = {
                    'ip': ip,
                    'hostname': socket.getfqdn(domain)
                }
            except socket.gaierror:
                pass
                
        except requests.RequestException as e:
            logger.error(f"Erro ao coletar informações de {url}: {str(e)}")
        
        return info
    
    def analyze_leaked_info(self, info):
        """
        Analisa informações vazadas que podem representar vulnerabilidades.
        
        Args:
            info (dict): Informações coletadas
            
        Returns:
            list: Lista de vulnerabilidades identificadas
        """
        vulnerabilities = []
        
        # Verificar comentários que podem conter informações sensíveis
        sensitive_patterns = [
            r'user(name)?',
            r'pass(word)?',
            r'key',
            r'api',
            r'token',
            r'secret',
            r'credent',
            r'auth',
            r'todo',
            r'fix',
            r'bug',
            r'issue',
            r'db',
            r'database',
            r'sql',
            r'update'
        ]
        
        suspicious_comments = []
        for comment in info['comments']:
            for pattern in sensitive_patterns:
                if re.search(pattern, comment, re.IGNORECASE):
                    suspicious_comments.append(comment)
                    break
        
        if suspicious_comments:
            vulnerability = {
                'type': 'information_disclosure',
                'name': 'Comentários HTML Sensíveis',
                'severity': 'medium',
                'location': info['url'],
                'description': 'Comentários HTML que podem conter informações sensíveis foram encontrados no código-fonte.',
                'evidence': '\n'.join(suspicious_comments[:5]) + ('...' if len(suspicious_comments) > 5 else ''),
                'cwe_id': 'CWE-615',
                'remediation': """
                1. Remova todos os comentários que contêm informações sensíveis, credenciais, TODOs ou FIXMEs do código em produção.
                2. Implemente um processo de revisão de código para garantir que comentários sensíveis não sejam publicados.
                3. Considere usar ferramentas de análise estática para detectar e remover comentários sensíveis automaticamente antes da implantação.
                """
            }
            vulnerabilities.append(vulnerability)
        
        # Verificar metadados que podem revelar informações sensíveis
        if info['metadata'].get('generator'):
            vulnerability = {
                'type': 'information_disclosure',
                'name': 'Divulgação de Tecnologia via Metadados',
                'severity': 'low',
                'location': info['url'],
                'description': 'A meta tag "generator" revela informações sobre a tecnologia utilizada.',
                'evidence': f"Generator: {info['metadata']['generator']}",
                'cwe_id': 'CWE-200',
                'remediation': """
                Remova ou modifique a meta tag "generator" para evitar a divulgação da tecnologia ou versão específica utilizada.
                """
            }
            vulnerabilities.append(vulnerability)
        
        # Verificar e-mails expostos
        if info['emails']:
            vulnerability = {
                'type': 'information_disclosure',
                'name': 'Endereços de E-mail Expostos',
                'severity': 'low',
                'location': info['url'],
                'description': 'Endereços de e-mail foram encontrados expostos no código-fonte da página.',
                'evidence': '\n'.join(info['emails'][:5]) + ('...' if len(info['emails']) > 5 else ''),
                'cwe_id': 'CWE-200',
                'remediation': """
                1. Evite incluir endereços de e-mail diretamente no código HTML.
                2. Considere o uso de formulários de contato em vez de links de e-mail diretos.
                3. Se necessário expor e-mails, considere ofuscá-los usando JavaScript ou outras técnicas para dificultar a coleta automatizada.
                """
            }
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def scan(self):
        """
        Executa o escaneamento de informações.
        
        Returns:
            list: Lista de vulnerabilidades encontradas
        """
        if not self.target_url:
            logger.error("URL alvo não especificada para Info Scanner")
            return []
            
        vulnerabilities = []
        
        # Coletar informações da URL principal
        info = self.collect_info(self.target_url)
        
        # Analisar informações para encontrar possíveis problemas
        vulns = self.analyze_leaked_info(info)
        vulnerabilities.extend(vulns)
        
        return vulnerabilities
