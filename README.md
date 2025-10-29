# 🛡️ WebSecScanner - Ferramenta de Avaliação de Segurança Web

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

## 🚀 Instalação e Configuração

### Pré-requisitos

- **Python 3.9+** instalado
- **Nmap** instalado (para reconhecimento de rede)
  - Windows: Baixar de [nmap.org](https://nmap.org/download.html)
  - O scanner irá procurar automaticamente em `C:\Program Files (x86)\Nmap\nmap.exe`

### Instalação

```bash
# Clone o repositório
git clone https://github.com/Franco-junior/afhacker.git
cd afhacker

# Crie e ative o ambiente virtual
python -m venv venv

# Windows
venv\Scripts\activate

# Linux/Mac
source venv/bin/activate

# Instale as dependências
pip install -r requirements.txt
```

### Executar o Projeto

```bash
# Iniciar o servidor FastAPI
python run.py

# O servidor estará disponível em:
# http://localhost:8000
# Ou em http://127.0.0.1:8000
```

### Primeiro Acesso

1. Acesse `http://localhost:8000` no navegador
2. Faça login com as credenciais padrão:
   - **Email:** `admin@websecscanner.com`
   - **Senha:** `admin123`
3. O usuário admin é criado automaticamente no primeiro start

## 💻 Uso

### Dashboard Web

1. Acesse `http://localhost:8000`
2. Faça login com as credenciais padrão
3. No painel principal você verá:
   - **Estatísticas**: Total de varreduras, vulnerabilidades, críticas e última varredura
   - **Iniciar Nova Varredura**: Digite a URL alvo e clique em "Iniciar Varredura"
   - **Varreduras Recentes**: Histórico de todas as varreduras realizadas

4. Para ver detalhes de uma varredura:
   - Clique em qualquer card de varredura
   - Navegue pelas abas:
     - **Visão Geral**: Informações da varredura e pontuação de risco
     - **Vulnerabilidades**: Lista detalhada com CVSS, localização e remediação
     - **Relatórios**: Download em JSON, HTML, CSV ou Markdown

### Linha de Comando

```bash
# Scan básico
python src/scanner.py --url https://example.com

# Scan completo com relatório
python src/scanner.py --url https://example.com --output report.json

# Exemplo de URL de teste
python src/scanner.py --url http://testphp.vulnweb.com
```

### O que o Scanner Detecta

O WebSecScanner executa os seguintes módulos automaticamente:

1. **Nmap Scanner** (Ferramenta Externa - Conceito B)
   - Reconhecimento de portas abertas
   - Detecção de serviços e versões
   - Identificação de software desatualizado

2. **SQL Injection**
   - Error-based SQLi
   - Boolean-based SQLi
   - Time-based SQLi

3. **Cross-Site Scripting (XSS)**
   - XSS Refletido
   - XSS Armazenado
   - XSS baseado em DOM

4. **CSRF (Cross-Site Request Forgery)**
   - Falta de tokens CSRF
   - Tokens previsíveis

5. **Path Traversal**
   - Directory Traversal
   - Local File Inclusion (LFI)

6. **Command Injection**
   - OS Command Injection
   - Code Injection

7. **Information Disclosure**
   - Exposição de informações sensíveis
   - Security misconfiguration

## 📊 Sistema de Pontuação

O WebSecScanner utiliza um sistema de pontuação de risco baseado em CVSS v3.1 com uma fórmula híbrida:

**Risk Score = (Max CVSS × 40%) + (Avg CVSS × 30%) + (Weighted Count × 30%)**

### Níveis de Risco

- **CRITICAL** (9.0-10.0): Requer ação imediata
- **HIGH** (7.0-8.9): Risco alto, correção prioritária
- **MEDIUM** (4.0-6.9): Risco moderado
- **LOW** (0.1-3.9): Risco baixo
- **INFO** (0.0): Informativo

### CVSS Score por Severidade

- **CRITICAL**: 9.0-10.0
- **HIGH**: 7.0-8.9
- **MEDIUM**: 4.0-6.9
- **LOW**: 2.0-3.9
- **INFO**: 0.1-1.9

## 📊 Exemplos de Saída

### Dashboard Web

Após uma varredura, o dashboard exibe:

```
📊 Estatísticas
├── Total de Varreduras: 5
├── Total de Vulnerabilidades: 12
├── Críticas: 2
└── Última Varredura: 28/10/2025

🔍 Detalhes da Varredura
├── URL Alvo: http://testphp.vulnweb.com
├── Pontuação de Risco: 6.2/10.0 (Overall)
├── Nível de Risco: HIGH
├── Total de Vulnerabilidades: 6
└── Duração: 45.3 segundos
```

### Terminal Output

```
🛡️  WebSecScanner v1.0.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Target: http://testphp.vulnweb.com
Scan ID: 550e8400-e29b-41d4-a716-446655440000

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[*] Starting Nmap reconnaissance...
[+] Found 3 open ports
[!] HIGH - Outdated Software Detected
    CVSS Score: 7.9

[*] Testing for SQL Injection...
[!] CRITICAL - SQL Injection Found
    Location: /search.php?id=1
    CVSS Score: 9.8

[*] Testing for XSS...
[+] 2 XSS vulnerabilities detected

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📊 Scan Summary:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Total Vulnerabilities: 6
├─ CRITICAL: 1
├─ HIGH: 1
├─ MEDIUM: 3
└─ LOW: 1

Risk Score: 6.2/10.0 (Overall)
Risk Level: HIGH

Scan Duration: 45.3 seconds
```

## 🛠️ Tecnologias Utilizadas

- **Backend:** Python 3.9+, FastAPI, Uvicorn
- **Frontend:** HTML5, CSS3, JavaScript (Vanilla)
- **Scanner:** Requests, BeautifulSoup4, Nmap (ferramenta externa)
- **Database:** SQLite com SQLAlchemy ORM
- **Autenticação:** JWT (PyJWT), bcrypt
- **Scoring:** Sistema CVSS-like customizado
- **CI/CD:** GitHub Actions

## 📁 Estrutura do Projeto

```
websecscanner/
├── src/
│   ├── scanner.py                # Scanner principal e orquestração
│   ├── report_generator.py       # Gerador de relatórios (JSON, CSV, HTML, MD)
│   ├── app.py                    # Aplicação FastAPI + rotas da API
│   ├── run.py                    # Script de inicialização
│   ├── utils/
│   │   ├── __init__.py
│   │   ├── http_client.py       # Cliente HTTP com retry e headers
│   │   ├── payloads.py          # Payloads de teste para vulnerabilidades
│   │   ├── scoring.py           # Sistema de scoring CVSS-like
│   │   └── auth.py              # Autenticação JWT e gerenciamento de usuários
│   ├── modules/
│   │   ├── __init__.py
│   │   ├── sqli_scanner.py      # SQL Injection (Error, Boolean, Time-based)
│   │   ├── xss_scanner.py       # XSS (Reflected, Stored, DOM)
│   │   ├── csrf_scanner.py      # CSRF Detection
│   │   ├── path_traversal.py    # Directory Traversal / LFI
│   │   ├── command_injection.py # OS Command Injection
│   │   ├── info_disclosure.py   # Information Disclosure
│   │   └── nmap_scanner.py      # Nmap Integration (Conceito B)
│   ├── database/
│   │   ├── __init__.py
│   │   ├── models.py            # Modelos SQLAlchemy (User, Scan, Vulnerability)
│   │   └── database.py          # Configuração e engine do banco
│   └── templates/
│       └── index.html           # Dashboard interativo (português)
├── docs/
│   ├── ARCHITECTURE.md          # Arquitetura detalhada
│   ├── API_DOCUMENTATION.md     # Documentação da API REST
│   ├── INSTALLATION_GUIDE.md    # Guia completo de instalação
│   ├── VIDEO_GUIDE.md           # Roteiro para vídeo de demonstração
│   └── RISK_SCORE_IMPROVEMENT.md # Explicação do sistema de scoring
├── .github/
│   └── workflows/
│       └── security_scan.yml    # Pipeline CI/CD automatizado
├── requirements.txt             # Dependências Python
├── .env.example                 # Exemplo de variáveis de ambiente
├── .gitignore                   # Arquivos ignorados pelo Git
├── run.py                       # Script principal de execução
└── README.md                    # Este arquivo
```

## 🔄 CI/CD Pipeline

O projeto inclui um pipeline automatizado via GitHub Actions que executa:

1. **Tests**: Testes unitários e cobertura de código
2. **Lint**: Verificação de qualidade (Black, Flake8, Pylint)
3. **Security Scan**: Trivy e Bandit para detectar vulnerabilidades
4. **Deploy**: Deploy automático após aprovação

O pipeline é acionado em:
- Push para branches `main` ou `develop`
- Pull Requests para `main`
- Diariamente às 2h AM (scan automático)

Ver `.github/workflows/security_scan.yml` para detalhes.

## 👥 Autor

- **Anderson Franco** - Avaliação Final de Tecnologias Hacker

## 🎓 Contexto Acadêmico

Este projeto foi desenvolvido como trabalho final da disciplina **Tecnologias Hackers**, atendendo aos requisitos para **Conceito A**:

✅ Detecção de vulnerabilidades OWASP Top 10  
✅ Dashboard interativo com autenticação  
✅ Sistema de scoring avançado (CVSS-like)  
✅ Relatórios profissionais em múltiplos formatos  
✅ Integração com ferramenta externa (Nmap) - **Conceito B**  
✅ Containerização e CI/CD  
✅ Documentação completa  


## 📚 Referências

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP ZAP](https://www.zaproxy.org/)
- [CVSS v3.1](https://www.first.org/cvss/)
- [CWE Top 25](https://cwe.mitre.org/top25/)