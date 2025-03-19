# WebSp1der

<p align="center">
  <img src="https://raw.githubusercontent.com/mairinkdev/WebSp1der/refs/heads/master/screenshots/interface.png" alt="WebSp1der Interface" width="650">
</p>

<p align="center">
  <b>Uma ferramenta profissional e open source para verificação de vulnerabilidades web</b>
</p>

## 📋 Índice

- [Visão Geral](#visão-geral)
- [Funcionalidades](#funcionalidades)
- [Modos de Uso](#modos-de-uso)
  - [Como Iniciar o WebSp1der](#como-iniciar-o-websp1der)
  - [Linha de Comando](#linha-de-comando)
  - [Interface Web](#interface-web)
- [Instalação](#instalação)
- [Tipos de Escaneamento](#tipos-de-escaneamento)
- [Detecção de Vulnerabilidades](#detecção-de-vulnerabilidades)
- [Configuração](#configuração)
- [Contribuição](#contribuição)
- [Licença](#licença)
- [Créditos](#créditos)

## 🌐 Visão Geral

WebSp1der é uma ferramenta avançada de segurança projetada para identificar, analisar e reportar vulnerabilidades em aplicações web. Combinando técnicas modernas de detecção e um design amigável, o WebSp1der oferece uma solução completa tanto para profissionais de segurança quanto para desenvolvedores que desejam verificar a segurança de suas aplicações.

A ferramenta foi desenvolvida com ênfase em:
- **Precisão**: Algoritmos avançados para minimizar falsos positivos
- **Eficiência**: Escaneamentos rápidos com uso otimizado de recursos
- **Usabilidade**: Interface intuitiva em dois formatos (CLI e Web)
- **Extensibilidade**: Arquitetura modular para fácil adição de novos tipos de escaneamento

## 🔍 Funcionalidades

- **Escaneamento Abrangente**: Detecção de múltiplas classes de vulnerabilidades
- **Geração de Relatórios**: Relatórios detalhados em formato JSON
- **Análise Personalizada**: Configure o nível de profundidade do escaneamento
- **Multi-threading**: Escaneamentos paralelos para maior eficiência
- **Crawling Inteligente**: Descoberta automática de páginas e formulários
- **Suporte a Proxy**: Compatível com proxies HTTP/HTTPS para testes anônimos
- **Classificação de Severidade**: Vulnerabilidades categorizadas por nível de risco

## 🖥️ Modos de Uso

O WebSp1der oferece dois modos de uso distintos para atender diferentes preferências e casos de uso:

### 🚀 Como Iniciar o WebSp1der

**Modo Interativo (Recomendado):**

```bash
# Iniciar o WebSp1der no modo interativo
python websp1der_cli.py
```

Este comando inicia o WebSp1der em modo interativo, detectando automaticamente o sistema operacional e perguntando se você deseja usar o modo de interface web ou linha de comando.

**Iniciar Diretamente:**

Você também pode iniciar diretamente o modo específico que deseja usar:

```bash
# Interface Web
python app_interface.py

# Linha de Comando
python app.py -u https://exemplo.com
```

### 🔤 Linha de Comando

O modo de linha de comando (CLI) é ideal para automação, integração com outras ferramentas ou uso em ambientes sem interface gráfica. Este modo é perfeito para usuários avançados, testes de segurança contínuos (CI/CD) e execução em servidores.

**Exemplo de uso no terminal/PowerShell:**

```bash
# Escaneamento básico
python app.py -u https://exemplo.com -a basic

# Escaneamento completo com relatório
python app.py -u https://exemplo.com -a full -o relatorio.json

# Uso com proxy e threads customizados
python app.py -u https://exemplo.com -a sqli -t 15 -p http://127.0.0.1:8080
```

**Opções disponíveis:**

```
-u, --url URL         URL alvo para análise (obrigatório)
-a, --analyze TYPE    Tipo de análise (basic, full, custom, xss, sqli, headers, port, csrf, info)
-o, --output FILE     Arquivo de saída para o relatório
-t, --threads NUM     Número de threads para análise paralela (padrão: 5)
-p, --proxy PROXY     Usar proxy (formato: http://host:porta)
-c, --config FILE     Arquivo de configuração personalizado
-h, --help            Mostra esta mensagem de ajuda
```

### 🌐 Interface Web

A interface web oferece uma experiência visual e interativa, perfeita para usuários que preferem uma representação gráfica dos resultados. Este modo é excelente para equipes, demonstrações e para usuários menos técnicos.

**Iniciando a interface web:**

```bash
# Interface web completa
python app_interface.py
```

Após iniciar, acesse a interface através do navegador em: `http://localhost:5000`

**Recursos da interface web:**

- **Dashboard visual**: Visualize vulnerabilidades por severidade
- **Escaneamento interativo**: Configure e inicie escaneamentos com poucos cliques
- **Progresso em tempo real**: Acompanhe o progresso do escaneamento
- **Resultados detalhados**: Visualização clara e organizada das vulnerabilidades
- **Exportação de relatórios**: Exporte resultados para análise posterior

## 📥 Instalação

```bash
# Clonar o repositório
git clone https://github.com/mairinkdev/WebSp1der.git
cd WebSp1der

# Instalar dependências
pip install -r requirements.txt
```

### Requisitos

- Python 3.8 ou superior
- Bibliotecas listadas em `requirements.txt`:
  - requests
  - flask
  - pyyaml
  - beautifulsoup4
  - colorama
  - urllib3

## 🔎 Tipos de Escaneamento

O WebSp1der oferece diferentes níveis de escaneamento:

- **Basic**: Escaneamento rápido focado em vulnerabilidades comuns (XSS, SQLi, Headers)
- **Full**: Escaneamento completo incluindo todas as verificações disponíveis
- **Custom**: Escaneamento personalizado baseado em configuração específica

## ⚠️ Detecção de Vulnerabilidades

O WebSp1der pode detectar múltiplas classes de vulnerabilidades, incluindo:

- **Injeção SQL (SQLi)**: Detecção de vulnerabilidades de injeção SQL baseada em erros e tempo
- **Cross-Site Scripting (XSS)**: Identificação de XSS refletido, armazenado e DOM-based
- **Cross-Site Request Forgery (CSRF)**: Verificação de proteções CSRF em formulários
- **Problemas em Headers de Segurança**: Análise de cabeçalhos HTTP de segurança ausentes ou mal configurados
- **Information Disclosure**: Detecção de informações sensíveis expostas
- **Server Misconfigurations**: Identificação de configurações incorretas no servidor

## ⚙️ Configuração

A configuração padrão está disponível em `config/default.yaml`. Para personalizar, crie uma cópia e modifique conforme necessário:

```yaml
general:
  threads: 5
  timeout: 10
  max_crawl_pages: 50
  verbose: false

scanners:
  xss:
    enabled: true
    payloads: 'default'
  sqli:
    enabled: true
    test_time_based: true
  # Outras configurações...
```

## 👥 Contribuição

Contribuições são bem-vindas! Por favor, sinta-se à vontade para:

1. Reportar bugs e problemas
2. Sugerir novas funcionalidades
3. Enviar pull requests com melhorias
4. Melhorar a documentação

## 📄 Licença

Este projeto está licenciado sob a [MIT License](LICENSE).

## 👨‍💻 Créditos

Desenvolvido com ❤️ por [mairinkdev](https://github.com/mairinkdev) 
