#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WebSp1der - Interface Web Simplificada
Desenvolvido por: mairinkdev (https://github.com/mairinkdev)
"""

import os
import json
import time
from flask import Flask, render_template, request, jsonify, session
import re

app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = os.urandom(24)

# Armazenar resultados de escaneamento (apenas para demonstração)
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
    
    # Validar URL
    if not target_url.startswith(('http://', 'https://')):
        return jsonify({'status': 'error', 'message': 'URL inválida! Use http:// ou https://'})
    
    # Gerar ID único para este escaneamento
    scan_id = str(int(time.time()))
    session['scan_id'] = scan_id
    
    # Simular início de escaneamento
    scan_status[scan_id] = {'status': 'running', 'progress': 0}
    
    # Em uma aplicação real, iniciaríamos uma thread aqui
    # Mas para fins de demonstração, vamos apenas simular um escaneamento com dados de exemplo
    simulate_scan(scan_id, target_url)
    
    return jsonify({
        'status': 'success', 
        'message': 'Escaneamento iniciado (modo demonstração)!',
        'scan_id': scan_id
    })

def simulate_scan(scan_id, url):
    """Simula um escaneamento com dados de exemplo para demonstração da interface."""
    # Iniciar com progresso 0
    scan_status[scan_id] = {'status': 'running', 'progress': 0}
    
    # Depois de 2 segundos, avançar para 30%
    time.sleep(2)
    scan_status[scan_id] = {'status': 'running', 'progress': 30}
    
    # Depois de mais 2 segundos, avançar para 70%
    time.sleep(2)
    scan_status[scan_id] = {'status': 'running', 'progress': 70}
    
    # Depois de mais 2 segundos, concluir
    time.sleep(2)
    
    # Extrair o domínio da URL para criar exemplos mais realistas
    domain = re.sub(r'^https?://', '', url)
    domain = domain.split('/')[0]  # Remove caminhos após o domínio
    
    # Gerar resultados de exemplo
    scan_results[scan_id] = {
        'vulnerabilities': [
            {
                'type': 'xss',
                'name': 'Cross-Site Scripting (XSS)',
                'url': f"https://{domain}/search.php",
                'parameter': 'q',
                'payload': '<script>alert(1)</script>',
                'severity': 'high',
                'description': 'O parâmetro "q" é vulnerável a Cross-Site Scripting (XSS)',
                'details': 'Encontrado XSS refletido no parâmetro de busca'
            },
            {
                'type': 'sqli',
                'name': 'SQL Injection',
                'url': f"https://{domain}/product.php",
                'parameter': 'id',
                'payload': "1' OR '1'='1",
                'severity': 'high',
                'description': 'O parâmetro "id" é vulnerável a SQL Injection',
                'details': 'A aplicação retorna dados diferentes quando injetado SQL'
            },
            {
                'type': 'headers',
                'name': 'Cabeçalhos de Segurança Ausentes',
                'url': url,
                'severity': 'medium',
                'description': 'Cabeçalhos de segurança importantes estão ausentes',
                'details': 'X-Frame-Options, Content-Security-Policy ausentes'
            },
            {
                'type': 'info',
                'name': 'Servidor Web Exposto',
                'url': url,
                'severity': 'low',
                'description': 'Informações de versão do servidor expostas',
                'details': 'Apache/2.4.41 (Ubuntu)'
            }
        ],
        'target_url': url,
        'scan_type': 'demonstração',
        'start_time': time.strftime('%Y-%m-%d %H:%M:%S'),
        'end_time': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() + 6)),
        'scan_duration': 6.0
    }
    
    # Marcar como concluído
    scan_status[scan_id] = {'status': 'completed', 'progress': 100}

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
    
    print("* WebSp1der Interface Web Simplificada")
    print("* MODO DE DEMONSTRAÇÃO - Escaneamentos simulados")
    print("* Acesse: http://localhost:5000")
    
    # Iniciar servidor
    app.run(debug=True, host='0.0.0.0', port=5000) 