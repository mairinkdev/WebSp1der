#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WebSp1der - Módulo de Utilidades
Desenvolvido por: mairinkdev (https://github.com/mairinkdev)
"""

import re
import random
import string
import socket
import logging
import hashlib
import urllib.parse
from urllib.parse import urlparse

logger = logging.getLogger('websp1der.utils')

class Utils:
    """Classe de utilitários para o WebSp1der."""
    
    @staticmethod
    def is_valid_url(url):
        """
        Verifica se uma URL é válida.
        
        Args:
            url (str): URL para verificar
            
        Returns:
            bool: True se a URL for válida, False caso contrário
        """
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except ValueError:
            return False
    
    @staticmethod
    def generate_random_string(length=10):
        """
        Gera uma string aleatória.
        
        Args:
            length (int): Comprimento da string a ser gerada
            
        Returns:
            str: String aleatória
        """
        charset = string.ascii_letters + string.digits
        return ''.join(random.choice(charset) for _ in range(length))
    
    @staticmethod
    def get_domain_from_url(url):
        """
        Extrai o domínio de uma URL.
        
        Args:
            url (str): URL para extrair o domínio
            
        Returns:
            str: Domínio extraído
        """
        try:
            parsed_url = urlparse(url)
            return parsed_url.netloc
        except (ValueError, AttributeError):
            logger.error(f"Erro ao extrair domínio da URL: {url}")
            return ""
    
    @staticmethod
    def normalize_url(url, base_url=None):
        """
        Normaliza uma URL.
        
        Args:
            url (str): URL para normalizar
            base_url (str, opcional): URL base para resolver caminhos relativos
            
        Returns:
            str: URL normalizada
        """
        if not url:
            return ""
        
        # Remover fragmentos
        url = url.split('#')[0]
        
        # Se começar com // (protocolo relativo)
        if url.startswith('//'):
            return 'http:' + url
        
        # Se for um caminho relativo e um base_url for fornecido
        if base_url and not url.startswith(('http://', 'https://')):
            base_parsed = urlparse(base_url)
            
            # Caminho absoluto
            if url.startswith('/'):
                return f"{base_parsed.scheme}://{base_parsed.netloc}{url}"
            
            # Caminho relativo
            base_path = '/'.join(base_parsed.path.split('/')[:-1]) + '/'
            return f"{base_parsed.scheme}://{base_parsed.netloc}{base_path}{url}"
        
        return url
    
    @staticmethod
    def extract_links_from_html(html_content):
        """
        Extrai links de conteúdo HTML.
        
        Args:
            html_content (str): Conteúdo HTML para extrair links
            
        Returns:
            list: Lista de links extraídos
        """
        # Regex simplificada para extrair href de tags 'a'
        link_pattern = re.compile(r'<a\s+(?:[^>]*?\s+)?href=(["\'])(.*?)\1', re.IGNORECASE)
        links = link_pattern.findall(html_content)
        return [link[1] for link in links]
    
    @staticmethod
    def extract_forms_from_html(html_content):
        """
        Extrai formulários de conteúdo HTML.
        
        Args:
            html_content (str): Conteúdo HTML para extrair formulários
            
        Returns:
            list: Lista de dicionários contendo informações sobre os formulários
        """
        # Regex simplificada para extrair formulários
        forms = []
        form_pattern = re.compile(r'<form\s+(?P<attrs>[^>]*)>(?P<content>.*?)</form>', re.IGNORECASE | re.DOTALL)
        input_pattern = re.compile(r'<input\s+(?P<attrs>[^>]*)/?>', re.IGNORECASE)
        action_pattern = re.compile(r'action=(["\'])(.*?)\1', re.IGNORECASE)
        method_pattern = re.compile(r'method=(["\'])(.*?)\1', re.IGNORECASE)
        name_pattern = re.compile(r'name=(["\'])(.*?)\1', re.IGNORECASE)
        type_pattern = re.compile(r'type=(["\'])(.*?)\1', re.IGNORECASE)
        
        form_matches = form_pattern.finditer(html_content)
        
        for form_match in form_matches:
            form_attrs = form_match.group('attrs')
            form_content = form_match.group('content')
            
            # Extrair action e method
            action_match = action_pattern.search(form_attrs)
            method_match = method_pattern.search(form_attrs)
            
            action = action_match.group(2) if action_match else ''
            method = method_match.group(2) if method_match else 'get'
            
            # Extrair campos de entrada
            inputs = []
            input_matches = input_pattern.finditer(form_content)
            
            for input_match in input_matches:
                input_attrs = input_match.group('attrs')
                name_match = name_pattern.search(input_attrs)
                type_match = type_pattern.search(input_attrs)
                
                name = name_match.group(2) if name_match else ''
                input_type = type_match.group(2) if type_match else ''
                
                if name:
                    inputs.append({
                        'name': name,
                        'type': input_type
                    })
            
            forms.append({
                'action': action,
                'method': method.lower(),
                'inputs': inputs
            })
        
        return forms
    
    @staticmethod
    def get_ip_from_domain(domain):
        """
        Resolve um domínio para um endereço IP.
        
        Args:
            domain (str): Domínio para resolver
            
        Returns:
            str: Endereço IP ou string vazia em caso de erro
        """
        try:
            return socket.gethostbyname(domain)
        except socket.gaierror:
            logger.error(f"Não foi possível resolver o domínio: {domain}")
            return ""
    
    @staticmethod
    def is_port_open(host, port, timeout=1):
        """
        Verifica se uma porta está aberta em um host.
        
        Args:
            host (str): Endereço do host
            port (int): Número da porta
            timeout (int, opcional): Tempo limite para a conexão em segundos
            
        Returns:
            bool: True se a porta estiver aberta, False caso contrário
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except (socket.error, socket.gaierror, OverflowError, TypeError):
            return False
    
    @staticmethod
    def generate_hash(text, algorithm='sha256'):
        """
        Gera o hash de um texto.
        
        Args:
            text (str): Texto para gerar hash
            algorithm (str, opcional): Algoritmo de hash (md5, sha1, sha256, sha512)
            
        Returns:
            str: Hash gerado
        """
        if algorithm == 'md5':
            return hashlib.md5(text.encode()).hexdigest()
        elif algorithm == 'sha1':
            return hashlib.sha1(text.encode()).hexdigest()
        elif algorithm == 'sha512':
            return hashlib.sha512(text.encode()).hexdigest()
        else:  # sha256 por padrão
            return hashlib.sha256(text.encode()).hexdigest()
    
    @staticmethod
    def get_file_extension(url):
        """
        Obtém a extensão de arquivo de uma URL.
        
        Args:
            url (str): URL para extrair a extensão do arquivo
            
        Returns:
            str: Extensão do arquivo ou string vazia se não houver extensão
        """
        path = urlparse(url).path
        ext = path.split('.')[-1] if '.' in path else ""
        return ext.lower()
    
    @staticmethod
    def urlencode(data):
        """
        Codifica dados para URL.
        
        Args:
            data (dict): Dados para codificar
            
        Returns:
            str: Dados codificados
        """
        return urllib.parse.urlencode(data)
    
    @staticmethod
    def urldecode(data):
        """
        Decodifica dados de URL.
        
        Args:
            data (str): Dados para decodificar
            
        Returns:
            dict: Dados decodificados
        """
        return dict(urllib.parse.parse_qsl(data))
    
    @staticmethod
    def is_common_web_file(url):
        """
        Verifica se uma URL aponta para um arquivo web comum.
        
        Args:
            url (str): URL para verificar
            
        Returns:
            bool: True se for um arquivo web comum, False caso contrário
        """
        common_extensions = {
            'html', 'htm', 'php', 'asp', 'aspx', 'jsp', 'do', 'cgi',
            'pl', 'js', 'css', 'xml', 'json', 'txt'
        }
        ext = Utils.get_file_extension(url)
        return ext in common_extensions
    
    @staticmethod
    def is_media_file(url):
        """
        Verifica se uma URL aponta para um arquivo de mídia.
        
        Args:
            url (str): URL para verificar
            
        Returns:
            bool: True se for um arquivo de mídia, False caso contrário
        """
        media_extensions = {
            'jpg', 'jpeg', 'png', 'gif', 'bmp', 'svg', 'webp',
            'mp3', 'wav', 'ogg', 'mp4', 'webm', 'avi', 'mov',
            'wmv', 'flv', 'pdf', 'doc', 'docx', 'xls', 'xlsx',
            'ppt', 'pptx', 'zip', 'rar', 'tar', 'gz'
        }
        ext = Utils.get_file_extension(url)
        return ext in media_extensions
    
    @staticmethod
    def is_same_domain(url1, url2):
        """
        Verifica se duas URLs pertencem ao mesmo domínio.
        
        Args:
            url1 (str): Primeira URL
            url2 (str): Segunda URL
            
        Returns:
            bool: True se as URLs pertencerem ao mesmo domínio, False caso contrário
        """
        domain1 = Utils.get_domain_from_url(url1)
        domain2 = Utils.get_domain_from_url(url2)
        return domain1 == domain2
    
    @staticmethod
    def extract_cookies_from_headers(headers):
        """
        Extrai cookies de cabeçalhos HTTP.
        
        Args:
            headers (dict): Cabeçalhos HTTP
            
        Returns:
            dict: Dicionário de cookies
        """
        cookies = {}
        cookie_header = headers.get('Set-Cookie', '')
        
        if not cookie_header:
            return cookies
        
        # Dividir múltiplos cookies
        cookie_parts = cookie_header.split(', ')
        
        for part in cookie_parts:
            # Extrair nome e valor do cookie
            cookie_items = part.split(';')
            if not cookie_items:
                continue
                
            name_value = cookie_items[0].split('=', 1)
            if len(name_value) != 2:
                continue
                
            name, value = name_value
            cookies[name.strip()] = value.strip()
        
        return cookies 