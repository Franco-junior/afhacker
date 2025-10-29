# 🚀 Como Iniciar o WebSecScanner

## ⚡ Acesso Rápido

O servidor já está rodando! Acesse:

### 🌐 URLs Importantes

- **Dashboard Web**: http://127.0.0.1:8000
- **Alternativa**: http://localhost:8000  
- **API Docs (Swagger)**: http://127.0.0.1:8000/docs
- **ReDoc**: http://127.0.0.1:8000/redoc

### 👤 Credenciais Padrão

```
Email: admin@websecscanner.com
Senha: admin123
```

---

## 🔧 Iniciar o Servidor

### Método 1: Script Launcher (Recomendado)
```powershell
python run.py
```

### Método 2: Diretamente
```powershell
python src/app.py
```

### Método 3: Com Uvicorn
```powershell
cd src
uvicorn app:app --host 127.0.0.1 --port 8000 --reload
```

---

## 🐛 Troubleshooting - Servidor não abre

### Problema: "Nada aparece no navegador"

**Causa**: No Windows, `0.0.0.0` não é acessível diretamente.

**Solução**: Use sempre `127.0.0.1` ou `localhost`:
- ✅ http://127.0.0.1:8000
- ✅ http://localhost:8000
- ❌ http://0.0.0.0:8000 (não funciona no Windows)

### Problema: "Connection Refused"

**Verifique se o servidor está rodando**:
```powershell
# Em outro terminal
curl http://127.0.0.1:8000/health
```

**Se não estiver rodando, inicie novamente**:
```powershell
python run.py
```

### Problema: "Port 8000 already in use"

**Solução 1**: Mate o processo existente
```powershell
# Encontre o PID
netstat -ano | findstr :8000

# Mate o processo (substitua PID pelo número encontrado)
taskkill /PID <PID> /F
```

**Solução 2**: Use outra porta
```powershell
$env:PORT=8080; python run.py
```

### Problema: "ModuleNotFoundError"

**Reinstale as dependências**:
```powershell
pip install -r requirements.txt
```

**Ou instale manualmente os principais**:
```powershell
pip install fastapi uvicorn sqlalchemy pydantic email-validator PyJWT passlib[bcrypt] requests beautifulsoup4 jinja2
```

### Problema: Warning sobre bcrypt

```
WARNING - (trapped) error reading bcrypt version
```

**Isso é apenas um warning, não afeta o funcionamento!** A aplicação continua normal.

Se quiser corrigir:
```powershell
pip uninstall bcrypt -y
pip install bcrypt==4.0.1
```

---

## 📋 Verificação de Saúde

### 1. Teste o endpoint de health
```powershell
curl http://127.0.0.1:8000/health
```

Resposta esperada:
```json
{
  "status": "healthy",
  "timestamp": "2025-10-28T19:00:00.000000"
}
```

### 2. Teste o login via API
```powershell
curl -X POST http://127.0.0.1:8000/api/auth/login `
  -H "Content-Type: application/json" `
  -d '{"email":"admin@websecscanner.com","password":"admin123"}'
```

### 3. Acesse a documentação interativa
http://127.0.0.1:8000/docs

---

## 🎯 Próximos Passos

1. ✅ Servidor rodando
2. ✅ Acesse http://127.0.0.1:8000
3. ✅ Faça login com admin@websecscanner.com / admin123
4. ✅ Crie um novo scan na interface
5. ✅ Veja os resultados em tempo real

---

## 🔥 Comandos Úteis

### Ver logs do servidor
O servidor mostra logs em tempo real no terminal onde foi iniciado.

### Recarregar após mudanças no código
```powershell
# Modo development com auto-reload
$env:DEBUG="true"; python run.py
```

### Parar o servidor
```
CTRL + C
```

### Limpar banco de dados
```powershell
Remove-Item websecscanner.db
python run.py  # Recria automaticamente
```

---

## 📱 Interface Web

### Tela de Login
![Login](docs/images/login.png)

**Recursos**:
- Login com email/senha
- Registro de novos usuários
- Autenticação JWT

### Dashboard Principal
![Dashboard](docs/images/dashboard.png)

**Métricas exibidas**:
- Total de scans realizados
- Total de vulnerabilidades encontradas
- Issues críticas
- Data do último scan

### Criar Novo Scan
![New Scan](docs/images/new-scan.png)

**Parâmetros**:
- URL alvo
- Tipos de scan (SQLi, XSS, CSRF, etc.)
- Iniciar scan imediatamente

### Resultados
![Results](docs/images/results.png)

**Informações**:
- Severidade (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- CVSS Score (0-10)
- Detalhes técnicos
- Recomendações de mitigação

---

## 🎓 Tutorial de Uso

### 1. Primeiro Acesso

1. Abra http://127.0.0.1:8000
2. Faça login com `admin@websecscanner.com` / `admin123`
3. Você será redirecionado para o dashboard

### 2. Criar um Scan

1. Clique em "New Scan"
2. Digite a URL alvo: `http://testphp.vulnweb.com`
3. Selecione os tipos de scan (ou deixe todos marcados)
4. Clique em "Start Scan"

### 3. Acompanhar Progresso

- O scan roda em background
- Dashboard atualiza automaticamente a cada 10 segundos
- Status possíveis: PENDING → RUNNING → COMPLETED → FAILED

### 4. Ver Resultados

1. Clique no scan na lista
2. Veja as vulnerabilidades encontradas
3. Clique em "View Details" para ver informações completas
4. Download do relatório em JSON/CSV/HTML/Markdown

---

## 🐳 Alternativa: Docker (Produção)

```powershell
# Iniciar com Docker Compose
docker-compose up -d

# Ver logs
docker-compose logs -f

# Parar
docker-compose down
```

Acesse: http://localhost:8000

---

## 💡 Dicas

- Use `testphp.vulnweb.com` para testes (site legalmente vulnerável)
- Nunca escaneie sites sem autorização!
- Para mais alvos de teste legais, veja: https://owasp.org/www-project-vulnerable-web-applications-directory/

---

**✅ Servidor Funcionando = Sucesso!**

Se você consegue acessar http://127.0.0.1:8000 e ver a tela de login, está tudo certo! 🎉
