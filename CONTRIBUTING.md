# Contributing to WebSecScanner

First off, thank you for considering contributing to WebSecScanner! It's people like you that make this tool better for everyone.

## Code of Conduct

By participating in this project, you are expected to uphold our Code of Conduct:
- Be respectful and inclusive
- Welcome diverse perspectives
- Focus on what is best for the community
- Show empathy towards other community members

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues. When creating a bug report, include:

- **Clear title and description**
- **Steps to reproduce**
- **Expected behavior**
- **Actual behavior**
- **Screenshots** (if applicable)
- **Environment details** (OS, Python version, etc.)

Example:
```markdown
**Title**: SQL Injection Scanner False Positive on Parameter X

**Description**: The SQL injection scanner reports a false positive when...

**Steps to Reproduce**:
1. Run scanner on URL: https://example.com/page?id=1
2. Observe false positive in parameter 'id'

**Expected**: No vulnerability should be detected
**Actual**: CRITICAL SQL Injection reported

**Environment**:
- OS: Windows 11
- Python: 3.11.5
- Scanner Version: 1.0.0
```

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, include:

- **Clear title and description**
- **Use case and rationale**
- **Proposed implementation** (if possible)
- **Alternatives considered**

### Pull Requests

1. **Fork the repository**
2. **Create a feature branch**
   ```bash
   git checkout -b feature/amazing-feature
   ```
3. **Make your changes**
4. **Run tests**
   ```bash
   pytest tests/ -v
   ```
5. **Commit your changes**
   ```bash
   git commit -m "Add amazing feature"
   ```
6. **Push to your fork**
   ```bash
   git push origin feature/amazing-feature
   ```
7. **Open a Pull Request**

## Development Setup

### Prerequisites
- Python 3.9+
- Git
- Docker (optional)

### Setup Development Environment

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/websecscanner.git
cd websecscanner

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# Install dependencies including dev tools
pip install -r requirements.txt
pip install -r requirements-dev.txt  # If exists

# Install pre-commit hooks
pip install pre-commit
pre-commit install
```

### Running Tests

```bash
# Run all tests
pytest tests/

# Run with coverage
pytest tests/ --cov=src --cov-report=html

# Run specific test file
pytest tests/test_scanner.py -v

# Run specific test
pytest tests/test_scanner.py::TestSecurityScanner::test_url_validation
```

### Code Style

We use the following tools for code quality:

```bash
# Format code with Black
black src/ tests/

# Check with flake8
flake8 src/ tests/ --max-line-length=120

# Type checking with mypy
mypy src/
```

## Project Structure

```
websecscanner/
├── src/
│   ├── modules/           # Scanner modules
│   │   ├── sqli_scanner.py
│   │   ├── xss_scanner.py
│   │   └── ...
│   ├── utils/             # Utilities
│   ├── database/          # Database models
│   ├── scanner.py         # Main scanner
│   ├── app.py            # FastAPI app
│   └── report_generator.py
├── tests/                 # Test files
├── docs/                  # Documentation
└── .github/              # CI/CD workflows
```

## Adding a New Scanner Module

1. **Create module file**: `src/modules/your_scanner.py`

```python
"""
Your Vulnerability Scanner Module
"""
import logging
from typing import List, Dict, Optional

from utils.http_client import HTTPClient
from utils.scoring import VulnerabilityType, calculate_vulnerability_score

logger = logging.getLogger(__name__)


class YourScanner:
    """Scanner for Your Vulnerability"""
    
    def __init__(self, http_client: HTTPClient):
        self.http_client = http_client
        self.vulnerabilities = []
    
    def scan(self, url: str, parameters: Optional[Dict] = None) -> List[Dict]:
        """Scan for vulnerabilities"""
        logger.info(f"Starting Your scan on {url}")
        self.vulnerabilities = []
        
        # Your scanning logic here
        
        return self.vulnerabilities
```

2. **Add tests**: `tests/test_your_scanner.py`

```python
import pytest
from src.modules.your_scanner import YourScanner
from src.utils.http_client import HTTPClient


class TestYourScanner:
    def setup_method(self):
        client = HTTPClient()
        self.scanner = YourScanner(client)
    
    def test_scanner_initialization(self):
        assert self.scanner is not None
    
    def test_scan_detects_vulnerability(self):
        results = self.scanner.scan('http://vulnerable-site.com')
        assert len(results) > 0
```

3. **Register in main scanner**: `src/scanner.py`

```python
from modules.your_scanner import YourScanner

# In SecurityScanner.__init__
self.scanners = {
    # ... existing scanners
    'your_vuln': YourScanner(self.http_client)
}
```

4. **Update documentation**

## Commit Message Guidelines

Follow conventional commits specification:

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types**:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

**Examples**:
```
feat(scanner): add XXE vulnerability detection

Implemented XML External Entity detection module with multiple payloads
and proper error handling.

Closes #123
```

```
fix(sqli): reduce false positives in boolean-based detection

Improved response comparison algorithm to reduce false positive rate
from 8% to 2%.

Fixes #456
```

## Documentation

When adding features:
- Update README.md
- Add docstrings to functions/classes
- Update technical_report.md if needed
- Add API documentation if adding endpoints

## Review Process

All pull requests go through review:
1. Automated tests must pass
2. Code must follow style guidelines
3. Documentation must be updated
4. At least one maintainer approval required

## Recognition

Contributors will be recognized in:
- README.md contributors section
- Release notes
- GitHub contributors page

## Questions?

- Open a discussion on GitHub
- Create an issue with "question" label
- Contact maintainers directly

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to WebSecScanner! 🛡️
