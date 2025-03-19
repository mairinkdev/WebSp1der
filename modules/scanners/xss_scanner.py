#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WebSp1der - Scanner de Cross-Site Scripting (XSS)
Desenvolvido por: mairinkdev (https://github.com/mairinkdev)
"""

import logging
import random
import re
import requests
from urllib.parse import urljoin, parse_qs, urlparse
from ..utils import Utils

logger = logging.getLogger('websp1der.scanners.xss')

class XSSScanner:
    """Scanner para detecção de vulnerabilidades de Cross-Site Scripting (XSS)."""

    def __init__(self):
        """Inicializa o scanner XSS."""
        self.name = "XSS Scanner"
        self.description = "Scanner para detecção de vulnerabilidades de Cross-Site Scripting (XSS)"

        # Payloads para teste de XSS
        self.payloads = [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            '\'><script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '"><img src=x onerror=alert(1)>',
            '\'><img src=x onerror=alert(1)>',
            '<svg/onload=alert(1)>',
            '"><svg/onload=alert(1)>',
            '\'><svg/onload=alert(1)>',
            '<body onload=alert(1)>',
            '"><body onload=alert(1)>',
            '\'><body onload=alert(1)>',
            '<details open ontoggle=alert(1)>',
            '"><details open ontoggle=alert(1)>',
            '\'><details open ontoggle=alert(1)>'
        ]

        # Marcadores únicos para identificar quando o payload é refletido
        self.xss_marker = 'WEBSP1DER-XSS-TEST'

        # Padrões para detectar scripts e eventos JS refletidos na resposta
        self.detect_patterns = [
            r'<script[^>]*>[^<]*alert\(1\)[^<]*</script>',
            r'<img[^>]*onerror=alert\(1)[^>]*>',
            r'<svg[^>]*onload=alert\(1)[^>]*>',
            r'<body[^>]*onload=alert\(1)[^>]*>',
            r'<details[^>]*ontoggle=alert\(1)[^>]*>'
        ]

    def check_response_for_xss(self, response_text):
        """
        Verifica se a resposta contém evidências de XSS bem-sucedido.

        Args:
            response_text (str): Texto da resposta HTTP

        Returns:
            bool: True se for detectado XSS, False caso contrário
        """
        # Verificar padrões de XSS
        for pattern in self.detect_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        
        return False

    def test_url_params(self, url, proxies=None, headers=None):
        """
        Testa vulnerabilidades XSS em parâmetros de URL.

        Args:
            url (str): URL para testar
            proxies (dict, opcional): Configuração de proxy
            headers (dict, opcional): Cabeçalhos HTTP

        Returns:
            list: Lista de vulnerabilidades encontradas
        """
        vulnerabilities = []
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        
        if not params:
            return vulnerabilities

        logger.debug(f"Testando XSS em parâmetros da URL: {url}")

        # Para cada parâmetro na URL
        for param, values in params.items():
            original_value = values[0] if values else ''
            
            # Testar com diferentes payloads
            for payload in self.payloads:
                # Construir nova URL com o payload
                new_params = params.copy()
                new_params[param] = [payload]
                
                query_string = '&'.join([f"{k}={v[0]}" for k, v in new_params.items()])
                test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{query_string}"
                
                try:
                    # Fazer a requisição
                    response = requests.get(
                        test_url,
                        headers=headers,
                        proxies=proxies,
                        timeout=10,
                        verify=False
                    )
                    
                    # Verificar se o XSS foi bem-sucedido
                    if self.check_response_for_xss(response.text):
                        logger.warning(f"XSS encontrado em {url}, parâmetro: {param}")
                        
                        # Criar relatório de vulnerabilidade
                        vulnerability = {
                            'type': 'xss',
                            'name': 'Cross-Site Scripting (XSS)',
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'severity': 'high',
                            'description': f"O parâmetro '{param}' é vulnerável a Cross-Site Scripting (XSS)",
                            'details': f"Payload usado: {payload}",
                            'recommendation': """
                            Para prevenir vulnerabilidades XSS:
                            1. Sanitizar todas as entradas de usuário antes de refletir no HTML.
                            2. Implementar Content Security Policy (CSP).
                            3. Usar o atributo HttpOnly para cookies.
                            4. Utilizar frameworks que escapam automaticamente a saída.
                            """
                        }
                        vulnerabilities.append(vulnerability)
                        break  # Pular para o próximo parâmetro após encontrar vulnerabilidade
                        
                except requests.RequestException as e:
                    logger.error(f"Erro ao testar XSS na URL {url}: {str(e)}")
                    continue
        
        return vulnerabilities

    def test_form(self, form, proxies=None, headers=None):
        """
        Testa vulnerabilidades XSS em formulários.

        Args:
            form (dict): Informações do formulário
            proxies (dict, opcional): Configuração de proxy
            headers (dict, opcional): Cabeçalhos HTTP

        Returns:
            list: Lista de vulnerabilidades encontradas
        """
        vulnerabilities = []
        
        if not form or 'inputs' not in form or not form['inputs']:
            return vulnerabilities
        
        logger.debug(f"Testando XSS em formulário: {form.get('url')}")
        
        # Obter detalhes do formulário
        form_url = form.get('url', '')
        form_action = form.get('action', '')
        form_method = form.get('method', 'get').lower()
        
        # Construir URL de ação
        if form_action.startswith('http'):
            action_url = form_action
        elif form_action.startswith('/'):
            parsed_url = urlparse(form_url)
            action_url = f"{parsed_url.scheme}://{parsed_url.netloc}{form_action}"
        else:
            action_url = urljoin(form_url, form_action) if form_action else form_url
        
        # Para cada campo no formulário
        for field in form['inputs']:
            field_name = field.get('name', '')
            field_type = field.get('type', '')
            
            # Ignorar campos de senha, arquivos, botões, etc.
            if field_type in ['password', 'file', 'submit', 'button', 'image', 'reset']:
                continue
            
            # Testar com diferentes payloads
            for payload in self.payloads:
                # Preparar dados do formulário
                form_data = {}
                for input_field in form['inputs']:
                    input_name = input_field.get('name', '')
                    # Se for o campo que estamos testando, use o payload
                    if input_name == field_name:
                        form_data[input_name] = payload
                    # Caso contrário, use um valor padrão baseado no tipo
                    elif input_field.get('type') == 'email':
                        form_data[input_name] = 'test@example.com'
                    else:
                        form_data[input_name] = 'test123'
                
                try:
                    # Enviar o formulário
                    if form_method == 'post':
                        response = requests.post(
                            action_url,
                            data=form_data,
                            headers=headers,
                            proxies=proxies,
                            timeout=10,
                            verify=False
                        )
                    else:  # método GET
                        response = requests.get(
                            action_url,
                            params=form_data,
                            headers=headers,
                            proxies=proxies,
                            timeout=10,
                            verify=False
                        )
                    
                    # Verificar se o XSS foi bem-sucedido
                    if self.check_response_for_xss(response.text):
                        logger.warning(f"XSS encontrado em formulário {action_url}, campo: {field_name}")
                        
                        # Criar relatório de vulnerabilidade
                        vulnerability = {
                            'type': 'xss',
                            'name': 'Cross-Site Scripting (XSS) em Formulário',
                            'url': action_url,
                            'parameter': field_name,
                            'payload': payload,
                            'severity': 'high',
                            'description': f"O campo '{field_name}' no formulário é vulnerável a Cross-Site Scripting (XSS)",
                            'details': f"Payload usado: {payload}",
                            'recommendation': """
                            Para prevenir vulnerabilidades XSS:
                            1. Sanitizar todas as entradas de usuário antes de refletir no HTML.
                            2. Implementar Content Security Policy (CSP).
                            3. Usar o atributo HttpOnly para cookies.
                            4. Utilizar frameworks que escapam automaticamente a saída.
                            """
                        }
                        vulnerabilities.append(vulnerability)
                        break  # Pular para o próximo campo após encontrar vulnerabilidade
                        
                except requests.RequestException as e:
                    logger.error(f"Erro ao testar XSS em formulário {action_url}: {str(e)}")
                    continue
        
        return vulnerabilities

    def scan(self, urls, forms, proxies=None, headers=None):
        """
        Executa o escaneamento de XSS em URLs e formulários.

        Args:
            urls (list): Lista de URLs para analisar
            forms (list): Lista de formulários para analisar
            proxies (dict, opcional): Configuração de proxy
            headers (dict, opcional): Cabeçalhos HTTP

        Returns:
            list: Lista de vulnerabilidades encontradas
        """
        vulnerabilities = []
        
        logger.info("Iniciando escaneamento de XSS...")
        
        # Testar URLs
        for url in urls:
            url_vulns = self.test_url_params(url, proxies, headers)
            vulnerabilities.extend(url_vulns)
        
        # Testar formulários
        for form in forms:
            form_vulns = self.test_form(form, proxies, headers)
            vulnerabilities.extend(form_vulns)
        
        logger.info(f"Escaneamento de XSS concluído. Encontradas {len(vulnerabilities)} vulnerabilidades.")
        
        return vulnerabilities 