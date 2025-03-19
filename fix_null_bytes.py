#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script para corrigir bytes problemáticos em arquivos.
"""
import os
import glob
import re

def fix_file(file_path):
    """Remove bytes problemáticos de um arquivo."""
    try:
        print(f"Verificando: {file_path}")
        
        # Tentar ler o arquivo como texto primeiro para ver se há erros
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                _ = f.read()
            print(f"Arquivo {file_path} parece estar OK como UTF-8.")
            return False
        except UnicodeDecodeError:
            print(f"Arquivo {file_path} tem problemas de codificação.")
        
        # Ler o arquivo como binário
        with open(file_path, 'rb') as f:
            content = f.read()
        
        # Criar uma versão limpa do arquivo (remover bytes não ASCII)
        # Vamos manter apenas ASCII básico e quebras de linha
        clean_content = b""
        for i in range(len(content)):
            byte = content[i:i+1]
            # Manter apenas ASCII printável, tabs, quebras de linha
            if (byte >= b' ' and byte <= b'~') or byte in (b'\n', b'\r', b'\t'):
                clean_content += byte
        
        # Se o conteúdo foi modificado, salvar o arquivo
        if clean_content != content:
            print(f"Bytes problemáticos encontrados em: {file_path}")
            
            # Garantir que o arquivo comece com um shebang válido
            if not clean_content.startswith(b'#!') and not clean_content.startswith(b'# -*-'):
                header = b"""#!/usr/bin/env python3
# -*- coding: utf-8 -*-
\"\"\"
WebSp1der - Scanner de Vulnerabilidades
Desenvolvido por: mairinkdev (https://github.com/mairinkdev)
\"\"\"

"""
                clean_content = header + clean_content
            
            # Salvar o arquivo limpo
            with open(file_path, 'wb') as f:
                f.write(clean_content)
            print(f"Arquivo corrigido: {file_path}")
            return True
        else:
            print(f"Nenhum byte problemático encontrado em: {file_path}")
            return False
    except Exception as e:
        print(f"Erro ao processar {file_path}: {str(e)}")
        return False

def recreate_init_file():
    """Recria o arquivo __init__.py com conteúdo limpo."""
    init_path = "modules/scanners/__init__.py"
    try:
        with open(init_path, 'w', encoding='utf-8') as f:
            f.write("""#!/usr/bin/env python3
# -*- coding: utf-8 -*-
\"\"\"
WebSp1der - Módulos de Escaneamento
Desenvolvido por: mairinkdev (https://github.com/mairinkdev)
\"\"\"

# Importar todos os scanners para facilitar o uso
from modules.scanners.xss_scanner import XSSScanner
from modules.scanners.sqli_scanner import SQLiScanner
from modules.scanners.headers_scanner import HeadersScanner
from modules.scanners.port_scanner import PortScanner
from modules.scanners.csrf_scanner import CSRFScanner
from modules.scanners.info_scanner import InfoScanner

__all__ = [
    'XSSScanner',
    'SQLiScanner',
    'HeadersScanner',
    'PortScanner',
    'CSRFScanner',
    'InfoScanner'
]
""")
        print(f"Arquivo {init_path} foi recriado com sucesso.")
        return True
    except Exception as e:
        print(f"Erro ao recriar {init_path}: {str(e)}")
        return False

def main():
    """Função principal."""
    # Recriar o arquivo __init__.py primeiro
    recreate_init_file()
    
    # Obter todos os arquivos Python em modules/scanners
    scanner_files = glob.glob("modules/scanners/*.py")
    
    # Adicionar outros arquivos importantes
    other_files = [
        "modules/scanner.py",
        "modules/utils.py",
        "modules/reporter.py",
        "websp1der.py",
        "app.py"
    ]
    
    all_files = scanner_files + other_files
    
    # Contar arquivos corrigidos
    fixed_count = 0
    
    # Processar cada arquivo
    for file_path in all_files:
        if os.path.exists(file_path):
            if fix_file(file_path):
                fixed_count += 1
    
    print(f"\nProcessamento concluído. {fixed_count} arquivos foram corrigidos.")
    print("Tente executar 'python app.py' ou 'python app_simple.py' agora.")

if __name__ == "__main__":
    main() 