# 🛡️ WebSecScanner - Ferramenta de Avaliação de Segurança Web

[![Security Scan](https://github.com/afhacker/websecscanner/workflows/Security%20Scan/badge.svg)](https://github.com/afhacker/websecscanner/actions)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue)](https://hub.docker.com/)
[![Python](https://img.shields.io/badge/Python-3.9+-green)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## 📋 Descrição

**WebSecScanner** é uma ferramenta avançada de avaliação de segurança automatizada para aplicações web, desenvolvida para identificar vulnerabilidades comuns descritas no OWASP Top 10.

### ✨ Funcionalidades Principais

- 🔍 **Detecção de Vulnerabilidades OWASP Top 10**
  - SQL Injection (SQLi)
  - Cross-Site Scripting (XSS - Refletido, Armazenado, DOM)
  - Cross-Site Request Forgery (CSRF)
  - Directory Traversal & Path Traversal
  - Local/Remote File Inclusion (LFI/RFI)
  - Command Injection
  - Exposure de Informações Sensíveis
  - Security Misconfiguration
  - Broken Authentication
  - XML External Entities (XXE)

- 📊 **Dashboard Interativo**
  - Visualização em tempo real dos scans
  - Gráficos de severidade e distribuição de vulnerabilidades
  - Score de risco calculado automaticamente
  - Filtros avançados por tipo, severidade e status

- 🎯 **Análise Heurística Avançada**
  - Priorização de vulnerabilidades por severidade (CVSS-like)
  - Recomendações automáticas de mitigação
  - Análise de impacto e exploitabilidade

- 👥 **Sistema Multi-Usuário**
  - Autenticação segura com JWT
  - Gerenciamento de empresas e projetos
  - Histórico completo de scans

- 📝 **Relatórios Profissionais**
  - Exportação em JSON, CSV, HTML e PDF
  - Relatórios técnicos detalhados
  - Sugestões de remediação específicas

- 🐳 **Containerização Completa**
  - Docker e Docker Compose prontos
  - Deploy simplificado
  - Isolamento e segurança

## 🏗️ Arquitetura

```
┌─────────────────────────────────────────────────────┐
│                   Web Dashboard                     │
│            (React/FastAPI Frontend)                 │
└─────────────────┬───────────────────────────────────┘
                  │
┌─────────────────▼───────────────────────────────────┐
│              FastAPI Backend                        │
│         (Authentication & API)                      │
└─────────────────┬───────────────────────────────────┘
                  │
┌─────────────────▼───────────────────────────────────┐
│            Security Scanner Engine                  │
│  ┌──────────┬──────────┬──────────┬──────────┐    │
│  │   SQLi   │   XSS    │  CSRF    │   RCE    │    │
│  │  Module  │  Module  │  Module  │  Module  │    │
│  └──────────┴──────────┴──────────┴──────────┘    │
│  ┌──────────┬──────────┬──────────┬──────────┐    │
│  │   Path   │   XXE    │  Auth    │  Config  │    │
│  │Traversal │  Module  │  Module  │  Module  │    │
│  └──────────┴──────────┴──────────┴──────────┘    │
└─────────────────┬───────────────────────────────────┘
                  │
┌─────────────────▼───────────────────────────────────┐
│           Report Generator                          │
│    (JSON, CSV, HTML, PDF, Markdown)                │
└─────────────────────────────────────────────────────┘
```

## 🚀 Instalação Rápida

### Opção 1: Docker (Recomendado)

```bash
# Clone o repositório
git clone https://github.com/afhacker/websecscanner.git
cd websecscanner

# Execute com Docker Compose
docker-compose up -d

# Acesse o dashboard
http://localhost:8000
```

### Opção 2: Instalação Manual

```bash
# Clone o repositório
git clone https://github.com/afhacker/websecscanner.git
cd websecscanner

# Crie ambiente virtual
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# Instale dependências
pip install -r requirements.txt

# Execute a aplicação
python src/app.py
```

## 💻 Uso

### Interface Web

Acesse `http://localhost:8000` e faça login com as credenciais padrão:
- **Usuário:** admin@websecscanner.com
- **Senha:** admin123

### Linha de Comando

```bash
# Scan básico
python src/scanner.py --url https://example.com

# Scan completo com todas as vulnerabilidades
python src/scanner.py --url https://example.com --full

# Scan específico
python src/scanner.py --url https://example.com --tests xss,sqli,csrf

# Exportar relatório
python src/scanner.py --url https://example.com --output report.json --format json
```

### API REST

```bash
# Criar novo scan
curl -X POST http://localhost:8000/api/scans \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com", "scan_type": "full"}'

# Obter resultados
curl http://localhost:8000/api/scans/{scan_id} \
  -H "Authorization: Bearer YOUR_TOKEN"
```

## 📊 Exemplos de Saída

### JSON Report
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "target_url": "https://vulnerable-app.com",
  "scan_date": "2025-10-28T10:30:00Z",
  "risk_score": 8.5,
  "vulnerabilities_found": 12,
  "vulnerabilities": [
    {
      "type": "SQL Injection",
      "severity": "CRITICAL",
      "cvss_score": 9.8,
      "location": "/login?user=admin",
      "payload": "' OR '1'='1",
      "evidence": "SQL error detected",
      "remediation": "Use parametrized queries..."
    }
  ]
}
```

## 🛠️ Tecnologias Utilizadas

- **Backend:** Python 3.9+, FastAPI
- **Frontend:** HTML5, CSS3, JavaScript, Chart.js
- **Scanner:** Requests, BeautifulSoup4, urllib3
- **Database:** SQLite (desenvolvimento), PostgreSQL (produção)
- **Autenticação:** JWT, bcrypt
- **Containerização:** Docker, Docker Compose
- **CI/CD:** GitHub Actions
- **Testes:** Pytest, Coverage

## 📁 Estrutura do Projeto

```
websecscanner/
├── src/
│   ├── scanner.py                 # Scanner principal
│   ├── report_generator.py        # Gerador de relatórios
│   ├── app.py                     # Aplicação FastAPI
│   ├── utils/
│   │   ├── __init__.py
│   │   ├── http_client.py        # Cliente HTTP customizado
│   │   ├── payloads.py           # Payloads de teste
│   │   ├── scoring.py            # Sistema de scoring
│   │   └── auth.py               # Autenticação JWT
│   ├── modules/
│   │   ├── __init__.py
│   │   ├── sqli_scanner.py       # SQL Injection
│   │   ├── xss_scanner.py        # Cross-Site Scripting
│   │   ├── csrf_scanner.py       # CSRF
│   │   ├── path_traversal.py     # Directory Traversal
│   │   ├── command_injection.py  # Command Injection
│   │   ├── xxe_scanner.py        # XXE
│   │   ├── auth_scanner.py       # Broken Auth
│   │   └── info_disclosure.py    # Info Disclosure
│   ├── database/
│   │   ├── __init__.py
│   │   ├── models.py             # Modelos SQLAlchemy
│   │   └── database.py           # Conexão DB
│   └── templates/
│       ├── index.html            # Dashboard
│       ├── login.html            # Login
│       └── report.html           # Template de relatório
├── tests/
│   ├── __init__.py
│   ├── test_scanner.py
│   ├── test_modules.py
│   └── test_api.py
├── docs/
│   ├── architecture_diagram.png
│   ├── flowchart.pdf
│   ├── technical_report.md
│   └── api_documentation.md
├── .github/
│   └── workflows/
│       └── security_scan.yml
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── .env.example
├── .gitignore
└── README.md
```

## 🧪 Testes

```bash
# Executar todos os testes
pytest

# Com cobertura
pytest --cov=src tests/

# Testes específicos
pytest tests/test_scanner.py -v
```

## 🔒 Segurança

⚠️ **AVISO IMPORTANTE:** Esta ferramenta deve ser utilizada APENAS para fins educacionais e em sistemas onde você tenha autorização explícita para realizar testes de segurança. O uso não autorizado pode ser ilegal.

## 📄 Licença

Este projeto está licenciado sob a MIT License - veja o arquivo [LICENSE](LICENSE) para detalhes.

## 👥 Autores

- **Franco** - Desenvolvimento e Arquitetura - [@afhacker](https://github.com/afhacker)

## 🙏 Agradecimentos

- OWASP Foundation
- Comunidade de Segurança da Informação
- Contribuidores Open Source

## 📚 Referências

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP ZAP](https://www.zaproxy.org/)
- [CVSS v3.1](https://www.first.org/cvss/)
- [CWE Top 25](https://cwe.mitre.org/top25/)

---

**⭐ Se este projeto foi útil, considere dar uma estrela no GitHub!**
