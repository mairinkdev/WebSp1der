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
    
    def __init__(self):
        """Inicializa o scanner CSRF."""
        self.name = "CSRF Scanner"
        self.description = "Scanner para detecção de vulnerabilidades de Cross-Site Request Forgery (CSRF)"
        
        # Padrões de tokens CSRF comuns
        self.csrf_token_patterns = [
            r'csrf[-_]token',
            r'csrf[-_]param',
            r'csrf[-_]key',
            r'csrf[-_]value',
            r'authenticity[-_]token',
            r'token',
            r'_token',
            r'csrfmiddlewaretoken',
            r'xsrf[-_]token',
            r'_csrf',
            r'__RequestVerificationToken'
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
        Analisa uma URL para vulnerabilidades CSRF.
        
        Args:
            url (str): URL para analisar
            proxies (dict, opcional): Configuração de proxy
            headers (dict, opcional): Cabeçalhos HTTP
            
        Returns:
            list: Lista de vulnerabilidades encontradas
        """
        vulnerabilities = []
        
        try:
            # Criar uma sessão para manter cookies
            session = requests.Session()
            if proxies:
                session.proxies.update(proxies)
            if headers:
                session.headers.update(headers)
            
            # Fazer requisição inicial
            response = session.get(
                url,
                timeout=10,
                verify=False  # Desabilitar verificação SSL para testes
            )
            
            # Verificar cabeçalhos relacionados a CSRF
            has_csrf_headers = self.check_csrf_headers(dict(response.headers))
            
            # Verificar tokens CSRF no HTML
            has_token_in_html = self.has_csrf_token(response.text, url)
            
            # Verificar configuração SameSite dos cookies
            has_same_site_cookies = self.check_same_site_cookies(response)
            
            # Se não encontrou proteções CSRF, pode ser vulnerável
            if not has_csrf_headers and not has_token_in_html and not has_same_site_cookies:
                # Parse HTML para extrair formulários
                soup = BeautifulSoup(response.text, 'html.parser')
                forms = soup.find_all('form', method=re.compile(r'post', re.IGNORECASE))
                
                if forms:
                    vulnerability = {
                        'type': 'csrf',
                        'name': 'Cross-Site Request Forgery (CSRF)',
                        'severity': 'medium',
                        'location': url,
                        'description': 'A página contém formulários POST sem proteção CSRF visível.',
                        'evidence': f"URL: {url}\nFormulários POST sem tokens CSRF: {len(forms)}",
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
                
            elif not has_same_site_cookies:
                # Se tem tokens CSRF, mas não tem SameSite=Strict, ainda há risco
                vulnerability = {
                    'type': 'csrf_partial',
                    'name': 'Proteção CSRF Parcial',
                    'severity': 'low',
                    'location': url,
                    'description': 'A página utiliza tokens CSRF, mas não implementa cookies com o atributo SameSite.',
                    'evidence': f"URL: {url}",
                    'cwe_id': 'CWE-352',
                    'remediation': """
                    Configure os cookies com o atributo SameSite=Strict ou SameSite=Lax para uma proteção adicional contra ataques CSRF.
                    """
                }
                vulnerabilities.append(vulnerability)
            
        except requests.RequestException as e:
            logger.error(f"Erro ao analisar CSRF em {url}: {str(e)}")
        
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
    
    def scan(self, urls, forms, proxies=None, headers=None):
        """
        Executa o escaneamento de CSRF em URLs e formulários.
        
        Args:
            urls (list): Lista de URLs para analisar
            forms (list): Lista de formulários para analisar
            proxies (dict, opcional): Configuração de proxy
            headers (dict, opcional): Cabeçalhos HTTP
            
        Returns:
            list: Lista de vulnerabilidades encontradas
        """
        vulnerabilities = []
        
        logger.info("Iniciando escaneamento de CSRF...")
        
        # Analisar URLs para encontrar formulários sem proteção CSRF
        for url in urls:
            url_vulns = self.scan_url(url, proxies, headers)
            vulnerabilities.extend(url_vulns)
        
        # Analisar formulários já extraídos
        for form in forms:
            form_vulns = self.scan_form(form, proxies, headers)
            vulnerabilities.extend(form_vulns)
        
        logger.info(f"Escaneamento de CSRF concluído. Encontradas {len(vulnerabilities)} vulnerabilidades.")
        
        return vulnerabilities 