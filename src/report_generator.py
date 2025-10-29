"""
Report Generator Module
Generates security scan reports in multiple formats
"""
import json
import csv
from datetime import datetime
from typing import Dict, List
from pathlib import Path
import logging

from utils.scoring import get_remediation, VulnerabilityType

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generate security scan reports in various formats"""
    
    def __init__(self, scan_results: Dict):
        """
        Initialize Report Generator
        
        Args:
            scan_results: Scan results dictionary
        """
        self.scan_results = scan_results
    
    def generate_json(self, output_file: str):
        """Generate JSON report"""
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(self.scan_results, f, indent=2, ensure_ascii=False)
            logger.info(f"JSON report saved to {output_file}")
        except Exception as e:
            logger.error(f"Error generating JSON report: {e}")
    
    def generate_csv(self, output_file: str):
        """Generate CSV report"""
        try:
            vulnerabilities = self.scan_results.get('vulnerabilities', [])
            
            if not vulnerabilities:
                logger.warning("No vulnerabilities to export")
                return
            
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                fieldnames = [
                    'type', 'subtype', 'severity', 'cvss_score', 
                    'location', 'parameter', 'payload', 
                    'description', 'remediation', 'confidence'
                ]
                
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                
                for vuln in vulnerabilities:
                    row = {
                        'type': vuln.get('type', ''),
                        'subtype': vuln.get('subtype', ''),
                        'severity': vuln.get('severity', ''),
                        'cvss_score': vuln.get('cvss_score', ''),
                        'location': vuln.get('location', ''),
                        'parameter': vuln.get('parameter', ''),
                        'payload': vuln.get('payload', '')[:100],
                        'description': vuln.get('description', ''),
                        'remediation': vuln.get('remediation', ''),
                        'confidence': vuln.get('confidence', '')
                    }
                    writer.writerow(row)
            
            logger.info(f"CSV report saved to {output_file}")
        
        except Exception as e:
            logger.error(f"Error generating CSV report: {e}")
    
    def generate_html(self, output_file: str):
        """Generate HTML report"""
        try:
            html_content = self._build_html_report()
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            logger.info(f"HTML report saved to {output_file}")
        
        except Exception as e:
            logger.error(f"Error generating HTML report: {e}")
    
    def generate_markdown(self, output_file: str):
        """Generate Markdown report"""
        try:
            md_content = self._build_markdown_report()
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(md_content)
            
            logger.info(f"Markdown report saved to {output_file}")
        
        except Exception as e:
            logger.error(f"Error generating Markdown report: {e}")
    
    def _build_html_report(self) -> str:
        """Build HTML report content"""
        result = self.scan_results
        
        html = f"""
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebSecScanner - Relatório de Segurança</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f5f5;
            color: #333;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
        }}
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .summary-card {{
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .summary-card h3 {{
            color: #667eea;
            margin-bottom: 10px;
            font-size: 0.9em;
            text-transform: uppercase;
        }}
        .summary-card .value {{
            font-size: 2em;
            font-weight: bold;
            color: #333;
        }}
        .risk-level {{
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: bold;
            text-transform: uppercase;
        }}
        .risk-CRITICAL {{ background: #dc3545; color: white; }}
        .risk-HIGH {{ background: #fd7e14; color: white; }}
        .risk-MEDIUM {{ background: #ffc107; color: #333; }}
        .risk-LOW {{ background: #28a745; color: white; }}
        .risk-INFO {{ background: #17a2b8; color: white; }}
        .vulnerabilities {{
            background: white;
            border-radius: 10px;
            padding: 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .vulnerability {{
            border-left: 4px solid #667eea;
            padding: 20px;
            margin-bottom: 20px;
            background: #f8f9fa;
            border-radius: 5px;
        }}
        .vulnerability.CRITICAL {{ border-left-color: #dc3545; }}
        .vulnerability.HIGH {{ border-left-color: #fd7e14; }}
        .vulnerability.MEDIUM {{ border-left-color: #ffc107; }}
        .vulnerability.LOW {{ border-left-color: #28a745; }}
        .vulnerability.INFO {{ border-left-color: #17a2b8; }}
        .vulnerability h3 {{
            color: #333;
            margin-bottom: 10px;
        }}
        .vulnerability .severity {{
            display: inline-block;
            padding: 3px 10px;
            border-radius: 15px;
            font-size: 0.85em;
            font-weight: bold;
            margin-right: 10px;
        }}
        .vulnerability .cvss {{
            display: inline-block;
            color: #666;
            font-size: 0.9em;
        }}
        .vulnerability .detail {{
            margin: 10px 0;
            color: #555;
        }}
        .vulnerability .detail strong {{
            color: #333;
            display: inline-block;
            min-width: 120px;
        }}
        .vulnerability .code {{
            background: #2d2d2d;
            color: #f8f8f2;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            margin: 10px 0;
        }}
        .vulnerability .remediation {{
            background: #e8f5e9;
            padding: 15px;
            border-radius: 5px;
            border-left: 3px solid #4caf50;
            margin-top: 15px;
        }}
        .vulnerability .remediation strong {{
            color: #2e7d32;
        }}
        .footer {{
            text-align: center;
            padding: 30px;
            color: #666;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Relatório de Varredura de Segurança</h1>
            <p>Alvo: {result.get('target_url', 'N/A')}</p>
            <p>Data da Varredura: {result.get('scan_date', 'N/A')}</p>
            <p>Duração: {result.get('scan_duration', 0):.2f} segundos</p>
        </div>
        
        <div class="summary">
            <div class="summary-card">
                <h3>Pontuação de Risco</h3>
                <div class="value">{result.get('risk_score', 0)}/10</div>
                <span class="risk-level risk-{result.get('risk_level', 'INFO')}">{result.get('risk_level', 'INFO')}</span>
            </div>
            <div class="summary-card">
                <h3>Vulnerabilidades Encontradas</h3>
                <div class="value">{result.get('vulnerabilities_found', 0)}</div>
            </div>
            <div class="summary-card">
                <h3>Críticas</h3>
                <div class="value" style="color: #dc3545;">{result.get('severity_distribution', {}).get('critical', 0)}</div>
            </div>
            <div class="summary-card">
                <h3>Alta Severidade</h3>
                <div class="value" style="color: #fd7e14;">{result.get('severity_distribution', {}).get('high', 0)}</div>
            </div>
        </div>
        
        <div class="vulnerabilities">
            <h2>Descobertas Detalhadas</h2>
            <p style="margin: 20px 0; color: #666;">
                Total de vulnerabilidades: 
                <strong>{result.get('severity_distribution', {}).get('critical', 0)}</strong> Críticas,
                <strong>{result.get('severity_distribution', {}).get('high', 0)}</strong> Alta,
                <strong>{result.get('severity_distribution', {}).get('medium', 0)}</strong> Média,
                <strong>{result.get('severity_distribution', {}).get('low', 0)}</strong> Baixa,
                <strong>{result.get('severity_distribution', {}).get('info', 0)}</strong> Info
            </p>
"""
        
        # Add vulnerabilities
        for i, vuln in enumerate(result.get('vulnerabilities', []), 1):
            severity = vuln.get('severity', 'INFO')
            html += f"""
            <div class="vulnerability {severity}">
                <h3>#{i} {vuln.get('type', 'Unknown')}</h3>
                <span class="severity risk-{severity}">{severity}</span>
                <span class="cvss">CVSS Score: {vuln.get('cvss_score', 'N/A')}</span>
                
                <div class="detail">
                    <strong>Subtype:</strong> {vuln.get('subtype', 'N/A')}
                </div>
                <div class="detail">
                    <strong>Location:</strong> {vuln.get('location', 'N/A')}
                </div>
"""
            
            if vuln.get('parameter'):
                html += f"""
                <div class="detail">
                    <strong>Parâmetro:</strong> {vuln.get('parameter', 'N/A')}
                </div>
"""
            
            html += f"""
                <div class="detail">
                    <strong>Descrição:</strong> {vuln.get('description', 'N/A')}
                </div>
"""
            
            if vuln.get('payload'):
                payload = str(vuln.get('payload', '')).replace('<', '&lt;').replace('>', '&gt;')
                html += f"""
                <div class="detail">
                    <strong>Payload:</strong>
                    <div class="code">{payload}</div>
                </div>
"""
            
            if vuln.get('evidence'):
                evidence = str(vuln.get('evidence', ''))[:300].replace('<', '&lt;').replace('>', '&gt;')
                html += f"""
                <div class="detail">
                    <strong>Evidência:</strong>
                    <div class="code">{evidence}...</div>
                </div>
"""
            
            html += f"""
                <div class="remediation">
                    <strong>🔧 Remediação:</strong> {vuln.get('remediation', 'N/A')}
                </div>
                <div class="detail" style="margin-top: 10px;">
                    <strong>Confiança:</strong> {vuln.get('confidence', 'N/A')}
                </div>
            </div>
"""
        
        html += """
        </div>
        
        <div class="footer">
            <p>Gerado por WebSecScanner v1.0.0</p>
            <p>⚠️ Este relatório contém informações sensíveis de segurança. Manuseie com cuidado.</p>
        </div>
    </div>
</body>
</html>
"""
        
        return html
    
    def _build_markdown_report(self) -> str:
        """Build Markdown report content"""
        result = self.scan_results
        
        md = f"""# 🛡️ WebSecScanner - Relatório de Segurança

## Informações da Varredura

- **URL Alvo:** {result.get('target_url', 'N/A')}
- **Data da Varredura:** {result.get('scan_date', 'N/A')}
- **Duração da Varredura:** {result.get('scan_duration', 0):.2f} segundos
- **ID da Varredura:** {result.get('scan_id', 'N/A')}

## Avaliação de Risco

- **Pontuação Geral de Risco:** {result.get('risk_score', 0)}/10
- **Nível de Risco:** **{result.get('risk_level', 'INFO')}**

## Resumo

| Severidade | Quantidade |
|------------|------------|
| Crítica    | {result.get('severity_distribution', {}).get('critical', 0)} |
| Alta       | {result.get('severity_distribution', {}).get('high', 0)} |
| Média      | {result.get('severity_distribution', {}).get('medium', 0)} |
| Baixa      | {result.get('severity_distribution', {}).get('low', 0)} |
| Info       | {result.get('severity_distribution', {}).get('info', 0)} |
| **Total**  | **{result.get('vulnerabilities_found', 0)}** |

---

## Descobertas Detalhadas

"""
        
        for i, vuln in enumerate(result.get('vulnerabilities', []), 1):
            md += f"""
### {i}. {vuln.get('type', 'Unknown')}

**Severidade:** `{vuln.get('severity', 'INFO')}` | **CVSS Score:** {vuln.get('cvss_score', 'N/A')}

- **Subtipo:** {vuln.get('subtype', 'N/A')}
- **Localização:** `{vuln.get('location', 'N/A')}`
"""
            
            if vuln.get('parameter'):
                md += f"- **Parâmetro:** `{vuln.get('parameter', 'N/A')}`\n"
            
            md += f"""
**Descrição:** {vuln.get('description', 'N/A')}

"""
            
            if vuln.get('payload'):
                md += f"""**Payload:**
```
{vuln.get('payload', '')}
```

"""
            
            if vuln.get('evidence'):
                md += f"""**Evidência:**
```
{str(vuln.get('evidence', ''))[:300]}...
```

"""
            
            md += f"""**🔧 Remediação:** {vuln.get('remediation', 'N/A')}

**Nível de Confiança:** {vuln.get('confidence', 'N/A')}

---

"""
        
        md += f"""
## Informações do Scanner

- **Scanner:** WebSecScanner v1.0.0
- **Módulos Utilizados:** {', '.join(result.get('scanner_info', {}).get('modules', []))}
- **Parâmetros Testados:** {result.get('parameters_tested', 0)}

---

*⚠️ Este relatório contém informações sensíveis de segurança. Manuseie com cuidado.*
"""
        
        return md
