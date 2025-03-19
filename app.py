#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WebSp1der - Interface Web
Desenvolvido por: mairinkdev (https://github.com/mairinkdev)
"""

import os
import json
import threading
import time
from flask import Flask, render_template, request, jsonify, session

# Importar o WebSp1der
import importlib.util
import sys
from pathlib import Path

# Garantir que o diretório raiz está no path
root_dir = Path(__file__).parent.absolute()
sys.path.append(str(root_dir))

# Importar o WebSp1der e seus componentes
from websp1der import WebSp1der

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
    proxy = request.form.get('proxy', '')
    
    # Validar URL
    if not target_url.startswith(('http://', 'https://')):
        return jsonify({'status': 'error', 'message': 'URL inválida! Use http:// ou https://'})
    
    # Gerar ID único para este escaneamento
    scan_id = str(int(time.time()))
    session['scan_id'] = scan_id
    
    # Configurar proxy se fornecido
    proxies = None
    if proxy:
        proxies = {
            'http': proxy,
            'https': proxy
        }
    
    # Criar configuração básica
    config = {
        'general': {
            'threads': threads,
            'timeout': timeout,
            'max_depth': 3
        }
    }
    
    # Iniciar escaneamento em uma thread separada
    scan_status[scan_id] = {'status': 'running', 'progress': 0}
    scan_thread = threading.Thread(
        target=run_scan, 
        args=(target_url, scan_type, proxies, config, scan_id)
    )
    scan_thread.daemon = True
    scan_thread.start()
    
    return jsonify({
        'status': 'success', 
        'message': 'Escaneamento iniciado!',
        'scan_id': scan_id
    })

def run_scan(url, scan_type, proxies, config, scan_id):
    try:
        # Inicializar o scanner
        scanner = WebSp1der(config)
        
        # Executar o escaneamento
        results = scanner.scan(url, scan_type=scan_type, proxies=proxies)
        
        # Armazenar resultados
        scan_results[scan_id] = results
        scan_status[scan_id] = {'status': 'completed', 'progress': 100}
    except Exception as e:
        scan_status[scan_id] = {
            'status': 'error', 
            'progress': 0, 
            'message': str(e)
        }

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