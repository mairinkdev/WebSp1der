#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WebSp1der - Módulo de Scanner
Desenvolvido por: mairinkdev (https://github.com/mairinkdev)
"""

import requests
import logging
import time
import random
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

# Importar os scanners individualmente sem usar o __init__.py
from modules.scanners.xss_scanner import XSSScanner
from modules.scanners.sqli_scanner import SQLiScanner  # Corrigido de SQLIScanner para SQLiScanner
from modules.scanners.csrf_scanner import CSRFScanner
from modules.scanners.headers_scanner import HeadersScanner
from modules.scanners.port_scanner import PortScanner
from modules.scanners.info_scanner import InfoScanner
from modules.utils import Utils

logger = logging.getLogger('websp1der.scanner')

class Scanner:
    """Classe principal de escaneamento que coordena os diferentes scanners."""

    def __init__(self, url, scan_type='basic', threads=5, proxy=None, config=None):
        """
        Inicializa o scanner.

        Args:
            url (str): URL alvo para análise
            scan_type (str): Tipo de análise (basic, full, custom)
            threads (int): Número de threads para análise paralela
            proxy (str): Proxy para usar nas requisições (formato: http://host:porta)
            config (dict): Configurações personalizadas
        """
        self.url = url
        self.scan_type = scan_type
        self.threads = threads

        # Configurar proxy
        self.proxies = None
        if proxy:
            self.proxies = {
                'http': proxy,
                'https': proxy
            }

        # Configurações
        self.config = config or {}
        self.timeout = self.config.get('timeout', 10)
        self.user_agents = self.config.get('user_agents', [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15'
        ])

        # Inicializar sub-scanners
        self.initialize_scanners()

        # Resultados
        self.results = {
            'target_url': url,
            'scan_type': scan_type,
            'start_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'end_time': None,
            'scan_duration': 0,
            'vulnerabilities': [],
            'information': {},
            'crawled_urls': [],
            'forms': []
        }

        logger.info(f"Scanner inicializado para {url} com modo {scan_type}")

    def initialize_scanners(self):
        """Inicializa os scanners com base no tipo de análise."""
        self.scanners = []

        # Scanners básicos sempre incluídos
        self.scanners.append(InfoScanner())
        self.scanners.append(HeadersScanner())

        if self.scan_type in ['basic', 'full', 'custom']:
            self.scanners.append(XSSScanner())
            self.scanners.append(SQLiScanner())  # Corrigido de SQLIScanner para SQLiScanner

        if self.scan_type in ['full', 'custom']:
            self.scanners.append(CSRFScanner())
            self.scanners.append(PortScanner())

        # Adicionar scanners personalizados da configuração
        if self.scan_type == 'custom' and 'custom_scanners' in self.config:
            for scanner_info in self.config['custom_scanners']:
                # Aqui implementaríamos lógica para carregar scanners personalizados
                pass

    def get_request_headers(self):
        """Obtém headers aleatórios para requisições."""
        headers = {
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        return headers

    def crawl(self, max_pages=50):
        """
        Realiza o crawling do site para descobrir URLs.

        Args:
            max_pages (int): Número máximo de páginas para crawlear

        Returns:
            list: Lista de URLs descobertas
        """
        logger.info(f"Iniciando crawling de {self.url}")

        discovered_urls = set()
        queued_urls = [self.url]
        visited_urls = set()

        base_url = urlparse(self.url).scheme + '://' + urlparse(self.url).netloc

        while queued_urls and len(visited_urls) < max_pages:
            current_url = queued_urls.pop(0)

            if current_url in visited_urls:
                continue

            logger.debug(f"Crawling: {current_url}")
            visited_urls.add(current_url)

            try:
                response = requests.get(
                    current_url,
                    headers=self.get_request_headers(),
                    proxies=self.proxies,
                    timeout=self.timeout,
                    verify=False  # Desabilitar verificação SSL para testes
                )

                if response.status_code != 200:
                    continue

                # Parse HTML
                soup = BeautifulSoup(response.text, 'html.parser')

                # Extrair links
                for link in soup.find_all('a', href=True):
                    href = link['href']

                    # Normalizar URL
                    if href.startswith('/'):
                        full_url = urljoin(base_url, href)
                    elif href.startswith('http'):
                        full_url = href
                    else:
                        full_url = urljoin(current_url, href)

                    # Verificar se é do mesmo domínio
                    if urlparse(self.url).netloc == urlparse(full_url).netloc:
                        discovered_urls.add(full_url)
                        if full_url not in visited_urls:
                            queued_urls.append(full_url)

                # Extrair formulários
                forms = soup.find_all('form')
                for form in forms:
                    form_data = {
                        'url': current_url,
                        'action': form.get('action', ''),
                        'method': form.get('method', 'get').lower(),
                        'inputs': []
                    }

                    # Extrair campos de entrada
                    for input_field in form.find_all(['input', 'textarea', 'select']):
                        field_type = input_field.get('type', '')
                        field_name = input_field.get('name', '')

                        if field_name:
                            form_data['inputs'].append({
                                'name': field_name,
                                'type': field_type
                            })

                    self.results['forms'].append(form_data)

            except requests.RequestException as e:
                logger.error(f"Erro ao crawlear {current_url}: {str(e)}")
                continue

        logger.info(f"Crawling concluído. Descobertas {len(discovered_urls)} URLs.")

        # Atualizar resultados
        self.results['crawled_urls'] = list(discovered_urls)
        return list(discovered_urls)

    def run_scanner(self, scanner, urls, forms):
        """
        Executa um scanner específico.

        Args:
            scanner: Instância do scanner
            urls (list): Lista de URLs para analisar
            forms (list): Lista de formulários para analisar

        Returns:
            list: Lista de vulnerabilidades encontradas
        """
        try:
            return scanner.scan(urls, forms, self.proxies, self.get_request_headers())
        except Exception as e:
            logger.error(f"Erro ao executar scanner {scanner.__class__.__name__}: {str(e)}")
            return []

    def run(self, progress=None, task=None):
        """
        Executa o escaneamento completo.

        Args:
            progress: Objeto de progresso (opcional)
            task: ID da tarefa para atualizar progresso (opcional)

        Returns:
            dict: Resultados do escaneamento
        """
        start_time = time.time()

        # Crawlear o site
        progress_value = 0
        progress_step = 30  # 30% para crawling

        if progress and task:
            progress.update(task, description="[cyan]Rastreando site...[/]", completed=progress_value)

        urls = self.crawl(max_pages=self.config.get('max_crawl_pages', 50))
        forms = self.results['forms']

        if progress and task:
            progress_value += progress_step
            progress.update(task, description="[cyan]Analisando vulnerabilidades...[/]", completed=progress_value)

        # Executar scanners em paralelo
        scanner_progress_step = (100 - progress_value) / len(self.scanners)

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            for scanner in self.scanners:
                futures.append(executor.submit(self.run_scanner, scanner, urls, forms))

            # Coletar resultados
            for i, future in enumerate(futures):
                vulns = future.result()
                self.results['vulnerabilities'].extend(vulns)

                if progress and task:
                    progress_value += scanner_progress_step
                    progress.update(task, completed=min(progress_value, 100))

        # Finalizar resultados
        end_time = time.time()
        self.results['end_time'] = time.strftime('%Y-%m-%d %H:%M:%S')
        self.results['scan_duration'] = round(end_time - start_time, 2)

        if progress and task:
            progress.update(task, description="[green]Análise concluída![/]", completed=100)

        return self.results 