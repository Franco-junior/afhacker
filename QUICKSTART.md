# 🚀 Quick Start Guide - WebSecScanner

## Instalação Rápida (5 minutos)

### Opção 1: Docker (Recomendado) 🐳

```bash
# 1. Clone o repositório
git clone https://github.com/afhacker/websecscanner.git
cd websecscanner

# 2. Inicie com Docker Compose
docker-compose up -d

# 3. Aguarde os containers iniciarem (30-60 segundos)
docker-compose logs -f websecscanner

# 4. Acesse o dashboard
# http://localhost:8000
```

**Credenciais padrão**:
- Email: `admin@websecscanner.com`
- Senha: `admin123`

### Opção 2: Instalação Manual 💻

#### Windows
```powershell
# 1. Clone o repositório
git clone https://github.com/afhacker/websecscanner.git
cd websecscanner

# 2. Crie ambiente virtual
python -m venv venv
venv\Scripts\activate

# 3. Instale dependências
pip install -r requirements.txt

# 4. Configure variáveis de ambiente
copy .env.example .env

# 5. Execute a aplicação
python src/app.py
```

#### Linux/Mac
```bash
# 1. Clone o repositório
git clone https://github.com/afhacker/websecscanner.git
cd websecscanner

# 2. Crie ambiente virtual
python3 -m venv venv
source venv/bin/activate

# 3. Instale dependências
pip install -r requirements.txt

# 4. Configure variáveis de ambiente
cp .env.example .env

# 5. Execute a aplicação
python src/app.py
```

## Uso Básico

### 1. Linha de Comando (CLI)

#### Scan Simples
```bash
python src/scanner.py --url https://example.com
```

#### Scan Completo com Todas as Vulnerabilidades
```bash
python src/scanner.py --url https://example.com --full
```

#### Scan Específico
```bash
python src/scanner.py --url https://example.com --tests sqli,xss,csrf
```

#### Gerar Relatório
```bash
# JSON
python src/scanner.py --url https://example.com --output report.json --format json

# HTML
python src/scanner.py --url https://example.com --output report.html --format html

# TXT
python src/scanner.py --url https://example.com --output report.txt --format txt
```

#### Ajuda
```bash
python src/scanner.py --help
```

### 2. Interface Web (Dashboard)

1. **Acessar Dashboard**
   ```
   http://localhost:8000
   ```

2. **Login**
   - Email: `admin@websecscanner.com`
   - Senha: `admin123`

3. **Iniciar Scan**
   - Inserir URL no campo "Start New Scan"
   - Clicar em "Start Scan"
   - Aguardar conclusão

4. **Visualizar Resultados**
   - Dashboard mostra métricas em tempo real
   - Lista de scans recentes
   - Detalhes de vulnerabilidades

### 3. API REST

#### Autenticação
```bash
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@websecscanner.com",
    "password": "admin123"
  }'
```

**Response**:
```json
{
  "access_token": "eyJhbGc...",
  "token_type": "bearer",
  "user": {...}
}
```

#### Criar Scan
```bash
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{
    "target_url": "https://example.com",
    "scan_types": ["sqli", "xss", "csrf"]
  }'
```

#### Listar Scans
```bash
curl http://localhost:8000/api/scans \
  -H "Authorization: Bearer YOUR_TOKEN"
```

#### Detalhes do Scan
```bash
curl http://localhost:8000/api/scans/1 \
  -H "Authorization: Bearer YOUR_TOKEN"
```

## Exemplos de Uso

### Exemplo 1: Testar Site de Demonstração
```bash
# Usar site vulnerável de propósito educacional
python src/scanner.py --url http://testphp.vulnweb.com --full
```

### Exemplo 2: Scan e Exportar para CSV
```bash
python src/scanner.py \
  --url https://your-test-site.com \
  --tests sqli,xss \
  --output vulnerabilities.csv \
  --format csv
```

### Exemplo 3: Integração com Python
```python
from src.scanner import SecurityScanner

# Criar scanner
scanner = SecurityScanner()

# Executar scan
results = scanner.scan('https://example.com')

# Visualizar resultados
print(f"Risk Score: {results['risk_score']}/10")
print(f"Vulnerabilities: {results['vulnerabilities_found']}")

# Salvar relatório
scanner.save_results('report.json', format='json')
```

### Exemplo 4: Gerar Múltiplos Relatórios
```python
from src.scanner import SecurityScanner
from src.report_generator import ReportGenerator

scanner = SecurityScanner()
results = scanner.scan('https://example.com')

generator = ReportGenerator(results)
generator.generate_html('report.html')
generator.generate_json('report.json')
generator.generate_csv('report.csv')
generator.generate_markdown('report.md')
```

## Troubleshooting

### Erro: "ModuleNotFoundError"
```bash
# Certifique-se de ativar o ambiente virtual
# Windows
venv\Scripts\activate

# Linux/Mac
source venv/bin/activate

# Reinstale dependências
pip install -r requirements.txt
```

### Erro: "Port 8000 already in use"
```bash
# Opção 1: Parar o processo na porta 8000
# Windows
netstat -ano | findstr :8000
taskkill /PID <PID> /F

# Linux/Mac
lsof -ti:8000 | xargs kill -9

# Opção 2: Usar outra porta
PORT=8080 python src/app.py
```

### Erro: "Database locked"
```bash
# Remover banco de dados existente
rm websecscanner.db

# Reiniciar aplicação
python src/app.py
```

### Erro: "SSL Certificate Verify Failed"
```bash
# Desabilitar verificação SSL (apenas para testes)
python src/scanner.py --url https://example.com --no-verify-ssl
```

## Configuração Avançada

### Variáveis de Ambiente (.env)
```bash
# Aplicação
APP_NAME=WebSecScanner
DEBUG=False
HOST=0.0.0.0
PORT=8000

# Segurança
SECRET_KEY=your-secret-key-here
JWT_SECRET_KEY=your-jwt-secret-key-here

# Database
DATABASE_URL=sqlite:///./websecscanner.db
# Para PostgreSQL:
# DATABASE_URL=postgresql://user:password@localhost/dbname

# Scanning
MAX_CONCURRENT_SCANS=5
REQUEST_TIMEOUT=10
MAX_RETRIES=3

# Logging
LOG_LEVEL=INFO
```

### Customizar Payloads
Edite `src/utils/payloads.py` para adicionar seus próprios payloads de teste.

### Adicionar Novos Módulos de Scan
1. Crie novo arquivo em `src/modules/`
2. Implemente classe com método `scan(url, parameters)`
3. Registre em `src/scanner.py`

## Melhores Práticas

### ✅ DO
- Sempre obter permissão antes de escanear
- Usar em ambientes de teste/desenvolvimento
- Documentar vulnerabilidades encontradas
- Compartilhar relatórios com equipe de segurança
- Configurar rate limiting adequado

### ❌ DON'T
- Escanear sites sem autorização
- Usar em produção sem cuidado
- Ignorar vulnerabilidades críticas
- Compartilhar relatórios publicamente
- Executar scans agressivos

## Suporte

### Documentação Completa
- **README.md**: Visão geral do projeto
- **docs/technical_report.md**: Relatório técnico detalhado
- **docs/api_documentation.md**: Documentação da API
- **docs/VIDEO_GUIDE.md**: Guia para vídeo de demonstração

### Logs
```bash
# Ver logs da aplicação
tail -f logs/websecscanner.log

# Ver logs do Docker
docker-compose logs -f
```

### Issues
Se encontrar problemas, abra uma issue no GitHub com:
1. Descrição do problema
2. Mensagem de erro completa
3. Sistema operacional
4. Versão do Python
5. Passos para reproduzir

## Atualizações

### Atualizar para Última Versão
```bash
# Git pull
git pull origin main

# Atualizar dependências
pip install -r requirements.txt --upgrade

# Reiniciar serviços
docker-compose down
docker-compose up -d --build
```

---

**⚠️ AVISO LEGAL**: Esta ferramenta deve ser usada apenas para fins educacionais e em sistemas onde você tem permissão explícita. O uso não autorizado pode ser ilegal.

**📧 Contato**: Para dúvidas ou sugestões, abra uma issue no GitHub.

**⭐ Star**: Se este projeto foi útil, considere dar uma estrela no GitHub!

---

Desenvolvido com ❤️ por Franco | Outubro 2025
