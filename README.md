# WebSp1der

Uma ferramenta profissional de verificação de vulnerabilidades web.

## Sobre

WebSp1der é uma ferramenta open source projetada para detectar vulnerabilidades em aplicações web. A ferramenta realiza verificações detalhadas para identificar problemas comuns de segurança como:

- Injeção SQL
- Cross-Site Scripting (XSS)
- Cross-Site Request Forgery (CSRF)
- Quebras de autenticação
- Configurações incorretas de segurança
- Vulnerabilidades em componentes desatualizados
- E muito mais...

## Características

- Interface de linha de comando intuitiva
- Análise detalhada de vulnerabilidades
- Geração de relatórios em vários formatos
- Baixo consumo de recursos
- Facilmente extensível através de plugins

## Instalação

```bash
pip install -r requirements.txt
```

## Uso

```bash
python websp1der.py -u https://exemplo.com -a full
```

## Opções

```
-u, --url URL         URL alvo para análise
-a, --analyze TYPE    Tipo de análise (basic, full, custom)
-o, --output FILE     Arquivo de saída para o relatório
-v, --verbose         Aumenta o nível de detalhes na saída
-t, --threads NUM     Número de threads para análise paralela
-p, --proxy PROXY     Usar proxy (formato: http://host:porta)
-h, --help            Mostra esta mensagem de ajuda
```

## Interface Web

O WebSp1der também possui uma interface web amigável que facilita a execução de escaneamentos e visualização de resultados:

```bash
# Iniciar a interface web
python app_simple.py
```

Após iniciar, acesse a interface através do navegador em: http://localhost:5000

A interface permite:
- Configurar e iniciar escaneamentos
- Visualizar resultados em tempo real com gráficos intuitivos
- Classificar vulnerabilidades por severidade
- Exportar relatórios em formato JSON

### Modo de Demonstração

A versão `app_simple.py` é uma versão de demonstração da interface web que simula escaneamentos sem depender de módulos externos. Ela é perfeita para:

- Testar a interface sem impactar sistemas reais
- Demonstrar as funcionalidades da ferramenta
- Servir como exemplo para desenvolvedores que desejam integrar seus próprios scanners

### Screenshots

![Interface Web](https://raw.githubusercontent.com/mairinkdev/websp1der/main/screenshots/interface.png)

## Contribuição

Contribuições são bem-vindas! Por favor, leia as diretrizes de contribuição antes de enviar um pull request.

## Licença

Este projeto está licenciado sob a [MIT License](LICENSE).

## Créditos

Desenvolvido por [mairinkdev](https://github.com/mairinkdev) 