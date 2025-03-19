#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WebSp1der - Interface Web
Desenvolvido por: mairinkdev (https://github.com/mairinkdev)
"""

import os
import json
import time
import threading
import requests
import urllib3
from flask import Flask, render_template, request, jsonify, session
import re

# Importar os scanners
from modules.scanners.xss_scanner import XSSScanner
from modules.scanners.sqli_scanner import SQLiScanner
from modules.scanners.headers_scanner import HeadersScanner
from modules.scanners.port_scanner import PortScanner
from modules.scanners.csrf_scanner import CSRFScanner
from modules.scanners.info_scanner import InfoScanner

# Desativar avisos SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = os.urandom(24)

# Armazenar resultados de escaneamento
scan_results = {}
scan_status = {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/start_scan', methods=['POST'])
def start_scan():
    # Obter dados do formulário
    target_url = request.form.get('url')
    scan_type = request.form.get('scan_type', 'full')
    threads = int(request.form.get('threads', 10))
    timeout = int(request.form.get('timeout', 10))
    proxy = request.form.get('proxy', None)
    
    # Validar URL
    if not target_url.startswith(('http://', 'https://')):
        return jsonify({'status': 'error', 'message': 'URL inválida! Use http:// ou https://'})
    
    # Gerar ID único para este escaneamento
    scan_id = str(int(time.time()))
    session['scan_id'] = scan_id
    
    # Iniciar escaneamento em uma thread separada
    scan_status[scan_id] = {'status': 'running', 'progress': 0}
    
    # Configurar proxy se fornecido
    proxies = None
    if proxy:
        proxies = {
            'http': proxy,
            'https': proxy
        }
    
    # Iniciar thread de escaneamento
    scan_thread = threading.Thread(
        target=run_scan,
        args=(scan_id, target_url, scan_type, threads, timeout, proxies)
    )
    scan_thread.daemon = True
    scan_thread.start()
    
    return jsonify({
        'status': 'success', 
        'message': 'Escaneamento iniciado!',
        'scan_id': scan_id
    })

def run_scan(scan_id, url, scan_type, threads, timeout, proxies):
    """Executa o escaneamento real usando os módulos de scanner."""
    try:
        # Inicializar resultado
        scan_results[scan_id] = {
            'vulnerabilities': [],
            'target_url': url,
            'scan_type': scan_type,
            'start_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'end_time': '',
            'scan_duration': 0.0
        }
        
        start_time = time.time()
        
        # Atualizar progresso
        scan_status[scan_id] = {'status': 'running', 'progress': 10}
        
        # Configurar session para requests
        session = requests.Session()
        if proxies:
            session.proxies.update(proxies)
        
        # Executar scanners com base no tipo de scan
        progress = 10
        total_scanners = 1 if scan_type != 'full' else 6
        progress_per_scanner = 80 / total_scanners
        
        # Escaneamento de XSS
        if scan_type == 'xss' or scan_type == 'full':
            xss_scanner = XSSScanner(url, threads=threads, timeout=timeout, session=session)
            xss_vulnerabilities = xss_scanner.scan()
            scan_results[scan_id]['vulnerabilities'].extend(xss_vulnerabilities)
            progress += progress_per_scanner
            scan_status[scan_id] = {'status': 'running', 'progress': int(progress)}
        
        # Escaneamento de SQL Injection
        if scan_type == 'sqli' or scan_type == 'full':
            sqli_scanner = SQLiScanner(url, threads=threads, timeout=timeout, session=session)
            sqli_vulnerabilities = sqli_scanner.scan()
            scan_results[scan_id]['vulnerabilities'].extend(sqli_vulnerabilities)
            progress += progress_per_scanner
            scan_status[scan_id] = {'status': 'running', 'progress': int(progress)}
        
        # Escaneamento de Cabeçalhos de Segurança
        if scan_type == 'headers' or scan_type == 'full':
            headers_scanner = HeadersScanner(url, session=session)
            headers_vulnerabilities = headers_scanner.scan()
            scan_results[scan_id]['vulnerabilities'].extend(headers_vulnerabilities)
            progress += progress_per_scanner
            scan_status[scan_id] = {'status': 'running', 'progress': int(progress)}
        
        # Escaneamento de Portas
        if scan_type == 'port' or scan_type == 'full':
            port_scanner = PortScanner(url, threads=threads, timeout=timeout)
            port_vulnerabilities = port_scanner.scan()
            scan_results[scan_id]['vulnerabilities'].extend(port_vulnerabilities)
            progress += progress_per_scanner
            scan_status[scan_id] = {'status': 'running', 'progress': int(progress)}
        
        # Escaneamento de CSRF
        if scan_type == 'csrf' or scan_type == 'full':
            csrf_scanner = CSRFScanner(url, threads=threads, timeout=timeout, session=session)
            csrf_vulnerabilities = csrf_scanner.scan()
            scan_results[scan_id]['vulnerabilities'].extend(csrf_vulnerabilities)
            progress += progress_per_scanner
            scan_status[scan_id] = {'status': 'running', 'progress': int(progress)}
        
        # Coleta de Informações
        if scan_type == 'info' or scan_type == 'full':
            info_scanner = InfoScanner(url, session=session)
            info_vulnerabilities = info_scanner.scan()
            scan_results[scan_id]['vulnerabilities'].extend(info_vulnerabilities)
            progress += progress_per_scanner
            scan_status[scan_id] = {'status': 'running', 'progress': int(progress)}
        
        # Finalizar escaneamento
        end_time = time.time()
        scan_duration = round(end_time - start_time, 2)
        
        scan_results[scan_id]['end_time'] = time.strftime('%Y-%m-%d %H:%M:%S')
        scan_results[scan_id]['scan_duration'] = scan_duration
        
        # Marcar como concluído
        scan_status[scan_id] = {'status': 'completed', 'progress': 100}
    
    except Exception as e:
        # Em caso de erro
        scan_status[scan_id] = {'status': 'error', 'progress': 0, 'message': str(e)}

@app.route('/scan_status')
def get_scan_status():
    scan_id = session.get('scan_id')
    if not scan_id or scan_id not in scan_status:
        return jsonify({'status': 'unknown'})
    
    return jsonify(scan_status[scan_id])

@app.route('/scan_results')
def get_scan_results():
    scan_id = session.get('scan_id')
    if not scan_id or scan_id not in scan_results:
        return jsonify({'status': 'no_results'})
    
    return jsonify({
        'status': 'success',
        'results': scan_results[scan_id]
    })

@app.route('/export_report', methods=['POST'])
def export_report():
    scan_id = session.get('scan_id')
    if not scan_id or scan_id not in scan_results:
        return jsonify({'status': 'error', 'message': 'Nenhum resultado disponível'})
    
    report_format = request.form.get('format', 'json')
    report_filename = f"websp1der_report_{scan_id}.{report_format}"
    report_path = os.path.join('reports', report_filename)
    
    os.makedirs('reports', exist_ok=True)
    
    with open(report_path, 'w', encoding='utf-8') as f:
        json.dump(scan_results[scan_id], f, indent=4, ensure_ascii=False)
    
    return jsonify({
        'status': 'success',
        'message': f'Relatório salvo como {report_filename}',
        'filename': report_filename
    })

if __name__ == '__main__':
    # Criar pastas necessárias
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static', exist_ok=True)
    os.makedirs('static/css', exist_ok=True)
    os.makedirs('static/js', exist_ok=True)
    os.makedirs('reports', exist_ok=True)
    
    print("* WebSp1der Interface Web")
    print("* Escaneamento real de vulnerabilidades")
    print("* Acesse: http://localhost:5000")
    
    # Iniciar servidor
    app.run(debug=True, host='0.0.0.0', port=5000) 