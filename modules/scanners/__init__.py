#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WebSp1der - Pacote de Scanners
Desenvolvido por: mairinkdev (https://github.com/mairinkdev)
"""

# Importar scanners para facilitar o acesso
from .xss_scanner import XSSScanner
from .sqli_scanner import SQLIScanner
from .csrf_scanner import CSRFScanner
from .headers_scanner import HeadersScanner
from .port_scanner import PortScanner
from .info_scanner import InfoScanner

__all__ = [
    'XSSScanner',
    'SQLIScanner',
    'CSRFScanner',
    'HeadersScanner',
    'PortScanner',
    'InfoScanner'
]
