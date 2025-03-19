#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WebSp1der - Scanner de CSRF (Cross-Site Request Forgery)
Desenvolvido por: mairinkdev (https://github.com/mairinkdev)
"""

import logging
import re
import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from ..utils import Utils

logger = logging.getLogger('websp1der.scanners.csrf')

class CSRFScanner:
    """Scanner para detecção de vulnerabilidades de Cross-Site Request Forgery (CSRF)."""
    
    def __init__(self, url=None, threads=5, timeout=10, session=None):
        """
        Inicializa o scanner CSRF.
        
        Args:
            url (str, opcional): URL alvo para escaneamento
            threads (int, opcional): Número de threads para escaneamento paralelo
            timeout (int, opcional): Timeout para requisições em segundos
            session (requests.Session, opcional): Sessão de requests para manter cookies/estado
        """
        self.name = "CSRF Scanner"
        self.description = "Scanner para detecção de vulnerabilidades de Cross-Site Request Forgery (CSRF)"
        self.target_url = url
        self.threads = threads
        self.timeout = timeout
        self.session = session or requests.Session()
        
        # Padrões de tokens CSRF comuns
        self.csrf_token_patterns = [
            r'csrf[-_]token',
            r'csrf[-_]param',
            r'csrf[-_]key',
            r'csrf[-_]value',
            r'csrf[-_]field',
            r'_token',
            r'authenticity_token',
            r'token',
            r'csrf',
            r'_csrf',
            r'xsrf',
            r'_xsrf',
            r'nonce'
        ]
        
        # Cabeçalhos relacionados a CSRF
        self.csrf_headers = [
            'X-CSRF-Token',
            'X-CSRFToken',
            'X-XSRF-TOKEN',
            'RequestVerificationToken'
        ]
    
    def has_csrf_token(self, html, url):
        """
        Verifica se um formulário possui um token CSRF.
        
        Args:
            html (str): Conteúdo HTML
            url (str): URL da página
            
        Returns:
            bool: True se encontrou token CSRF, False caso contrário
        """
        try:
            soup = BeautifulSoup(html, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms:
                # Verificar campos hidden que podem conter tokens CSRF
                hidden_inputs = form.find_all('input', {'type': 'hidden'})
                
                for hidden_input in hidden_inputs:
                    input_name = hidden_input.get('name', '').lower()
                    
                    # Verificar se o nome do campo corresponde a um padrão de token CSRF
                    for pattern in self.csrf_token_patterns:
                        if re.search(pattern, input_name, re.IGNORECASE):
                            return True
                
                # Também verificar em atributos data-* que alguns frameworks usam
                data_attrs = [attr for attr in form.attrs if attr.startswith('data-')]
                for attr in data_attrs:
                    for pattern in self.csrf_token_patterns:
                        if re.search(pattern, attr, re.IGNORECASE) or re.search(pattern, form[attr], re.IGNORECASE):
                            return True
            
            # Também verificar meta tags que podem conter tokens CSRF
            meta_tags = soup.find_all('meta')
            for tag in meta_tags:
                for pattern in self.csrf_token_patterns:
                    if (tag.get('name') and re.search(pattern, tag.get('name'), re.IGNORECASE)) or \
                       (tag.get('id') and re.search(pattern, tag.get('id'), re.IGNORECASE)):
                        return True
            
            return False
            
        except Exception as e:
            logger.error(f"Erro ao analisar tokens CSRF em {url}: {str(e)}")
            return False
    
    def check_csrf_headers(self, headers):
        """
        Verifica se os cabeçalhos da resposta contêm tokens CSRF.
        
        Args:
            headers (dict): Cabeçalhos da resposta HTTP
            
        Returns:
            bool: True se encontrou token CSRF nos cabeçalhos, False caso contrário
        """
        for header in self.csrf_headers:
            if header in headers:
                return True
        
        # Verificar tokens em cookies
        if 'Set-Cookie' in headers:
            for pattern in self.csrf_token_patterns:
                if re.search(pattern, headers['Set-Cookie'], re.IGNORECASE):
                    return True
        
        return False
    
    def check_same_site_cookies(self, response):
        """
        Verifica se os cookies têm o atributo SameSite configurado.
        
        Args:
            response (requests.Response): Resposta HTTP
            
        Returns:
            bool: True se todos os cookies tiverem o atributo SameSite, False caso contrário
        """
        if not response.cookies:
            return False
        
        for cookie in response.cookies:
            if not cookie.has_nonstandard_attr('SameSite'):
                return False
        
        return True
    
    def check_vulnerable_form(self, form, url, session=None):
        """
        Verifica se um formulário é vulnerável a CSRF.
        
        Args:
            form (dict): Informações do formulário
            url (str): URL da página
            session (requests.Session, opcional): Sessão HTTP
            
        Returns:
            bool: True se o formulário é vulnerável, False caso contrário
        """
        form_url = form.get('url', '')
        form_action = form.get('action', '')
        form_method = form.get('method', 'get').lower()
        form_inputs = form.get('inputs', [])
        
        # Formulários GET normalmente não são considerados vulneráveis a CSRF
        if form_method == 'get':
            return False
        
        # Se não tem URL ou campos, não é vulnerável
        if not form_url or not form_inputs:
            return False
        
        # Resolver URL completa da ação do formulário
        if form_action:
            action_url = urljoin(url, form_action)
        else:
            action_url = url
        
        # Verificar se o formulário tem algum token CSRF
        has_csrf_token = False
        for input_field in form_inputs:
            field_name = input_field.get('name', '').lower()
            
            for pattern in self.csrf_token_patterns:
                if re.search(pattern, field_name, re.IGNORECASE):
                    has_csrf_token = True
                    break
            
            if has_csrf_token:
                break
        
        if has_csrf_token:
            return False
        
        # Se chegou aqui, o formulário não tem proteção CSRF visível
        # Para validar, podemos tentar fazer uma requisição
        if session:
            try:
                # Preparar dados do formulário (valores simulados)
                form_data = {}
                for input_field in form_inputs:
                    field_name = input_field.get('name', '')
                    field_type = input_field.get('type', '').lower()
                    
                    if not field_name:
                        continue
                    
                    # Preencher com valores padrão para simulação
                    if field_type == 'email':
                        form_data[field_name] = 'test@example.com'
                    elif field_type == 'number':
                        form_data[field_name] = '123'
                    elif field_type in ['checkbox', 'radio']:
                        form_data[field_name] = 'on'
                    else:
                        form_data[field_name] = 'test'
                
                # Tentar enviar o formulário
                response = session.post(
                    action_url,
                    data=form_data,
                    timeout=10,
                    verify=False,  # Desabilitar verificação SSL para testes
                    allow_redirects=False
                )
                
                # Se a requisição foi bem-sucedida (2xx, 3xx), o formulário pode ser vulnerável
                if 200 <= response.status_code < 400:
                    return True
                
            except requests.RequestException as e:
                logger.error(f"Erro ao testar formulário CSRF em {action_url}: {str(e)}")
        
        # Se não podemos testar ativamente, considere vulnerável com base na análise estática
        return True
    
    def scan_url(self, url, proxies=None, headers=None):
        """
        Analisa uma URL para verificar proteções CSRF.
        
        Args:
            url (str): URL para analisar
            proxies (dict, opcional): Configuração de proxy
            headers (dict, opcional): Cabeçalhos HTTP
            
        Returns:
            list: Lista de vulnerabilidades encontradas
        """
        vulnerabilities = []
        
        try:
            logger.debug(f"Verificando CSRF em URL: {url}")
            
            # Fazer requisição para obter a página
            response = self.session.get(
                url, 
                headers=headers,
                proxies=proxies,
                timeout=self.timeout,
                verify=False  # Desabilitar verificação SSL para testes
            )
            
            if response.status_code != 200:
                return vulnerabilities
            
            # Verificar cabeçalhos relacionados a CSRF
            if not self.check_csrf_headers(response.headers):
                vulnerability = {
                    'type': 'csrf_headers',
                    'name': 'Falta de Proteção CSRF em Cabeçalhos',
                    'url': url,
                    'severity': 'medium',
                    'description': 'A aplicação não implementa cabeçalhos para prevenção de CSRF.',
                    'details': "Cabeçalhos como 'X-Frame-Options' e 'Content-Security-Policy' podem ajudar a mitigar ataques CSRF.",
                    'recommendation': """
                    Implementar cabeçalhos de segurança para ajudar na prevenção de CSRF:
                    1. X-Frame-Options: DENY ou SAMEORIGIN
                    2. Content-Security-Policy com diretivas apropriadas
                    """
                }
                vulnerabilities.append(vulnerability)
            
            # Verificar cookies SameSite
            if not self.check_same_site_cookies(response):
                vulnerability = {
                    'type': 'csrf_cookies',
                    'name': 'Cookies sem Atributo SameSite',
                    'url': url,
                    'severity': 'medium',
                    'description': 'Os cookies não têm o atributo SameSite configurado.',
                    'details': "O atributo SameSite ajuda a prevenir ataques CSRF ao controlar quando os cookies são enviados em requisições cross-site.",
                    'recommendation': """
                    Configurar o atributo SameSite=Lax ou SameSite=Strict para cookies de sessão e autenticação.
                    """
                }
                vulnerabilities.append(vulnerability)
            
            # Extrair e verificar formulários na página
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms:
                # Verificar se o formulário é vulnerável a CSRF
                if not self.has_csrf_token(str(form), url):
                    # Obter detalhes do formulário
                    form_action = form.get('action', '')
                    if not form_action:
                        form_action = url
                    elif not form_action.startswith(('http://', 'https://')):
                        form_action = urljoin(url, form_action)
                    
                    form_method = form.get('method', 'get').upper()
                    form_id = form.get('id', '')
                    form_name = form.get('name', '')
                    form_description = f"Formulário {form_id if form_id else form_name if form_name else 'sem id/nome'} ({form_method})"
                    
                    # Adicionar vulnerabilidade
                    vulnerability = {
                        'type': 'csrf_form',
                        'name': 'Formulário sem Proteção CSRF',
                        'url': url,
                        'severity': 'high' if form_method == 'POST' else 'medium',
                        'description': f"{form_description} não tem proteção contra CSRF.",
                        'details': f"Ação do formulário: {form_action}",
                        'recommendation': """
                        Implementar proteção CSRF para o formulário:
                        1. Adicionar token CSRF em campos ocultos.
                        2. Validar o token no servidor.
                        3. Usar frameworks que incluem proteção CSRF automaticamente.
                        """
                    }
                    vulnerabilities.append(vulnerability)
                    
        except requests.RequestException as e:
            logger.error(f"Erro ao analisar URL {url} para CSRF: {str(e)}")
            
        return vulnerabilities
    
    def scan_form(self, form, proxies=None, headers=None):
        """
        Analisa um formulário para vulnerabilidades CSRF.
        
        Args:
            form (dict): Informações do formulário
            proxies (dict, opcional): Configuração de proxy
            headers (dict, opcional): Cabeçalhos HTTP
            
        Returns:
            list: Lista de vulnerabilidades encontradas
        """
        vulnerabilities = []
        
        form_url = form.get('url', '')
        form_action = form.get('action', '')
        form_method = form.get('method', 'get').lower()
        
        if not form_url or form_method != 'post':
            return vulnerabilities
        
        # Resolver URL completa da ação do formulário
        if form_action:
            action_url = urljoin(form_url, form_action)
        else:
            action_url = form_url
        
        # Criar uma sessão para manter cookies
        session = requests.Session()
        if proxies:
            session.proxies.update(proxies)
        if headers:
            session.headers.update(headers)
        
        # Verificar se o formulário é vulnerável
        is_vulnerable = self.check_vulnerable_form(form, form_url, session)
        
        if is_vulnerable:
            vulnerability = {
                'type': 'csrf',
                'name': 'Cross-Site Request Forgery (CSRF)',
                'severity': 'medium',
                'location': f"Formulário em {form_url} (ação: {action_url})",
                'description': 'O formulário POST não possui proteção CSRF adequada.',
                'evidence': f"Formulário sem token CSRF: Método={form_method}, Ação={form_action}",
                'cwe_id': 'CWE-352',
                'remediation': """
                1. Implemente tokens CSRF em todos os formulários POST.
                2. Garanta que os tokens sejam únicos por sessão e por requisição.
                3. Verifique os tokens no servidor para cada requisição.
                4. Configure cookies com o atributo SameSite=Strict ou SameSite=Lax.
                5. Implemente cabeçalhos CORS apropriados.
                6. Considere implementar verificação de Referer/Origin.
                """
            }
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def scan(self):
        """
        Executa o escaneamento de CSRF.
        
        Returns:
            list: Lista de vulnerabilidades encontradas
        """
        if not self.target_url:
            logger.error("URL alvo não especificada para CSRF Scanner")
            return []
            
        vulnerabilities = []
        
        # Escanear a URL principal
        csrf_vulns = self.scan_url(self.target_url)
        vulnerabilities.extend(csrf_vulns)
        
        return vulnerabilities 