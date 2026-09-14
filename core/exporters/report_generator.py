"""Report generation and export module for binary analysis."""

import os
import json
import csv
import logging
import datetime
from typing import Dict, List, Any, Optional, Union
from dataclasses import asdict
from pathlib import Path

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False
    logging.warning("PyYAML not available for YAML export")

try:
    import html
    from jinja2 import Template
    HAS_HTML = True
except ImportError:
    HAS_HTML = False
    logging.warning("Jinja2 not available for HTML report generation")

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generates various report formats from analysis results."""
    
    def __init__(self, analysis_results: Dict[str, Any]):
        self.results = analysis_results
        self.timestamp = datetime.datetime.now().isoformat()
    
    def generate_json_report(self, output_path: str) -> bool:
        """Generate JSON report."""
        try:
            report_data = self._prepare_report_data()
            report_data["report_generated"] = self.timestamp
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, default=str)
            
            logger.info(f"JSON report saved to: {output_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to generate JSON report: {e}")
            return False
    
    def generate_yaml_report(self, output_path: str) -> bool:
        """Generate YAML report."""
        if not HAS_YAML:
            logger.warning("YAML export not available (PyYAML not installed)")
            return False
        
        try:
            report_data = self._prepare_report_data()
            report_data["report_generated"] = self.timestamp
            
            with open(output_path, 'w', encoding='utf-8') as f:
                yaml.dump(report_data, f, default_flow_style=False)
            
            logger.info(f"YAML report saved to: {output_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to generate YAML report: {e}")
            return False
    
    def generate_html_report(self, output_path: str) -> bool:
        """Generate HTML report."""
        if not HAS_HTML:
            logger.warning("HTML export not available (Jinja2 not installed)")
            return False
        
        try:
            report_data = self._prepare_report_data()
            report_data["report_generated"] = self.timestamp
            
            # Create HTML template
            html_template = self._get_html_template()
            template = Template(html_template)
            html_content = template.render(report=report_data)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            logger.info(f"HTML report saved to: {output_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to generate HTML report: {e}")
            return False
    
    def generate_csv_report(self, output_path: str) -> bool:
        """Generate CSV report with summary data."""
        try:
            report_data = self._prepare_report_data()
            
            # Extract key data for CSV
            csv_data = self._extract_csv_data(report_data)
            
            if not csv_data:
                logger.warning("No data available for CSV report")
                return False
            
            # Write CSV file
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                if csv_data:
                    fieldnames = csv_data[0].keys()
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(csv_data)
            
            logger.info(f"CSV report saved to: {output_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to generate CSV report: {e}")
            return False
    
    def generate_markdown_report(self, output_path: str) -> bool:
        """Generate Markdown report."""
        try:
            report_data = self._prepare_report_data()
            
            md_content = self._generate_markdown_content(report_data)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(md_content)
            
            logger.info(f"Markdown report saved to: {output_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to generate Markdown report: {e}")
            return False
    
    def export_all_formats(self, output_dir: str, prefix: str = "analysis") -> Dict[str, str]:
        """Export reports in all available formats."""
        os.makedirs(output_dir, exist_ok=True)
        
        exported_files = {}
        
        # Generate JSON report
        json_path = os.path.join(output_dir, f"{prefix}_report.json")
        if self.generate_json_report(json_path):
            exported_files["json"] = json_path
        
        # Generate YAML report if available
        if HAS_YAML:
            yaml_path = os.path.join(output_dir, f"{prefix}_report.yaml")
            if self.generate_yaml_report(yaml_path):
                exported_files["yaml"] = yaml_path
        
        # Generate HTML report if available
        if HAS_HTML:
            html_path = os.path.join(output_dir, f"{prefix}_report.html")
            if self.generate_html_report(html_path):
                exported_files["html"] = html_path
        
        # Generate CSV report
        csv_path = os.path.join(output_dir, f"{prefix}_summary.csv")
        if self.generate_csv_report(csv_path):
            exported_files["csv"] = csv_path
        
        # Generate Markdown report
        md_path = os.path.join(output_dir, f"{prefix}_report.md")
        if self.generate_markdown_report(md_path):
            exported_files["markdown"] = md_path
        
        return exported_files
    
    def _prepare_report_data(self) -> Dict[str, Any]:
        """Prepare report data from analysis results."""
        report_data = {
            "analysis_timestamp": self.timestamp,
            "tool_version": "1.0.0",
            "analysis_results": self.results
        }
        
        # Add summary statistics
        if "binary_info" in self.results:
            binary_info = self.results["binary_info"]
            report_data["summary"] = self._generate_summary(binary_info)
        
        return report_data
    
    def _generate_summary(self, binary_info: Union[Dict[str, Any], Any]) -> Dict[str, Any]:
        """Generate summary statistics from binary info."""
        if hasattr(binary_info, '__dataclass_fields__'):
            try:
                b_info = asdict(binary_info)
            except Exception:
                b_info = vars(binary_info)
        elif isinstance(binary_info, dict):
            b_info = binary_info
        else:
            b_info = getattr(binary_info, '__dict__', {})

        arch = b_info.get("architecture", "unknown")
        if hasattr(arch, "value"):
            arch = arch.value

        sections = b_info.get("sections", []) or []
        functions = b_info.get("functions", []) or []
        imports = b_info.get("imports", []) or []
        exports = b_info.get("exports", []) or []
        strings = b_info.get("strings", []) or []

        summary = {
            "file_type": str(arch),
            "entry_point": b_info.get("entry_point", 0),
            "section_count": len(sections),
            "function_count": len(functions),
            "import_count": len(imports),
            "export_count": len(exports),
            "string_count": len(strings),
        }
        
        # Calculate additional statistics
        if sections:
            executable_sections = [
                s for s in sections 
                if (isinstance(s, dict) and s.get("is_executable", False)) or getattr(s, "is_executable", False)
            ]
            summary["executable_sections"] = len(executable_sections)
            
            # Calculate total code size
            code_size = sum(
                s.get("size", 0) if isinstance(s, dict) else getattr(s, "size", 0)
                for s in executable_sections
            )
            summary["estimated_code_size"] = code_size
        
        # Entropy analysis
        entropy = b_info.get("entropy_analysis", {}) or {}
        if isinstance(entropy, dict) and entropy:
            overall_ent = entropy.get("overall", 0)
            summary["entropy"] = {
                "overall": round(overall_ent, 3) if isinstance(overall_ent, (int, float)) else 0,
                "high_entropy": overall_ent > 7.0 if isinstance(overall_ent, (int, float)) else False
            }
        
        return summary
    
    def _extract_csv_data(self, report_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract data for CSV report."""
        csv_data = []
        
        # Add summary row
        summary = report_data.get("summary", {})
        if summary:
            csv_data.append({
                "category": "summary",
                "name": "file_summary",
                "value": json.dumps(summary),
                "count": 1
            })
        
        # Extract sections
        binary_info = report_data.get("analysis_results", {}).get("binary_info", {})
        sections = binary_info.get("sections", [])
        for section in sections:
            csv_data.append({
                "category": "section",
                "name": section.get("name", "unknown"),
                "value": f"VA: 0x{section.get('address', 0):x}, Size: {section.get('size', 0)}",
                "count": 1
            })
        
        # Extract imports
        imports = binary_info.get("imports", [])
        for imp in imports:
            csv_data.append({
                "category": "import",
                "name": imp.get("function", "unknown"),
                "value": imp.get("dll", "unknown"),
                "count": 1
            })
        
        # Extract exports
        exports = binary_info.get("exports", [])
        for exp in exports:
            csv_data.append({
                "category": "export",
                "name": exp.get("name", "unknown"),
                "value": f"Address: 0x{exp.get('address', 0):x}",
                "count": 1
            })
        
        return csv_data
    
    def _generate_markdown_content(self, report_data: Dict[str, Any]) -> str:
        """Generate Markdown report content."""
        md_lines = []
        
        # Header
        md_lines.append("# Binary Analysis Report")
        md_lines.append(f"*Generated: {report_data['analysis_timestamp']}*")
        md_lines.append(f"*Tool Version: {report_data['tool_version']}*")
        md_lines.append("")
        
        # Summary
        summary = report_data.get("summary", {})
        if summary:
            md_lines.append("## Summary")
            md_lines.append("")
            
            md_lines.append("| Metric | Value |")
            md_lines.append("|--------|-------|")
            for key, value in summary.items():
                if isinstance(value, dict):
                    value_str = json.dumps(value, indent=2)
                else:
                    value_str = str(value)
                md_lines.append(f"| {key} | {value_str} |")
            md_lines.append("")
        
        # Binary Information
        binary_info = report_data.get("analysis_results", {}).get("binary_info", {})
        if binary_info:
            md_lines.append("## Binary Information")
            md_lines.append("")
            
            md_lines.append(f"**Architecture:** {binary_info.get('architecture', 'unknown')}")
            md_lines.append(f"**Entry Point:** 0x{binary_info.get('entry_point', 0):x}")
            md_lines.append("")
            
            # Sections
            sections = binary_info.get("sections", [])
            if sections:
                md_lines.append("### Sections")
                md_lines.append("")
                md_lines.append("| Name | Address | Size | Executable |")
                md_lines.append("|------|---------|------|------------|")
                for section in sections:
                    md_lines.append(f"| {section.get('name')} | 0x{section.get('address', 0):x} | {section.get('size')} | {'✓' if section.get('is_executable') else '✗'} |")
                md_lines.append("")
            
            # Functions
            functions = binary_info.get("functions", [])
            if functions:
                md_lines.append("### Functions")
                md_lines.append("")
                md_lines.append("| Name | Address | Size |")
                md_lines.append("|------|---------|------|")
                for func in functions[:20]:  # Limit to 20 functions
                    md_lines.append(f"| {func.get('name')} | 0x{func.get('address', 0):x} | {func.get('size')} |")
                
                if len(functions) > 20:
                    md_lines.append(f"*... and {len(functions) - 20} more functions*")
                md_lines.append("")
            
            # Strings
            strings = binary_info.get("strings", [])
            if strings:
                md_lines.append("### Extracted Strings")
                md_lines.append("")
                md_lines.append("| Address | String |")
                md_lines.append("|---------|--------|")
                for string_info in strings[:50]:  # Limit to 50 strings
                    string = string_info.get("string", "")
                    if len(string) > 50:
                        string = string[:47] + "..."
                    md_lines.append(f"| 0x{string_info.get('address', 0):x} | `{string}` |")
                
                if len(strings) > 50:
                    md_lines.append(f"*... and {len(strings) - 50} more strings*")
                md_lines.append("")
        
        return "\n".join(md_lines)
    
    def _get_html_template(self) -> str:
        """Get HTML template for report generation."""
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Binary Analysis Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            padding: 30px;
        }
        
        .header {
            text-align: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 2px solid #eaeaea;
        }
        
        .header h1 {
            color: #2c3e50;
            margin-bottom: 10px;
        }
        
        .header .meta {
            color: #7f8c8d;
            font-size: 0.9em;
        }
        
        .section {
            margin-bottom: 30px;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 6px;
            border-left: 4px solid #3498db;
        }
        
        .section h2 {
            color: #2c3e50;
            margin-bottom: 15px;
            display: flex;
            align-items: center;
        }
        
        .section h2 i {
            margin-right: 10px;
            color: #3498db;
        }
        
        .card {
            background: white;
            border-radius: 6px;
            padding: 15px;
            margin-bottom: 15px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        
        .card h3 {
            color: #2c3e50;
            margin-bottom: 10px;
            font-size: 1.1em;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        
        .stat-card {
            background: white;
            padding: 15px;
            border-radius: 6px;
            text-align: center;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            border-top: 3px solid #3498db;
        }
        
        .stat-value {
            font-size: 2em;
            font-weight: bold;
            color: #2c3e50;
            margin: 10px 0;
        }
        
        .stat-label {
            color: #7f8c8d;
            font-size: 0.9em;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }
        
        th {
            background-color: #3498db;
            color: white;
            text-align: left;
            padding: 12px;
            font-weight: 600;
        }
        
        td {
            padding: 12px;
            border-bottom: 1px solid #eaeaea;
        }
        
        tr:nth-child(even) {
            background-color: #f8f9fa;
        }
        
        tr:hover {
            background-color: #e3f2fd;
        }
        
        .badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .badge.success {
            background-color: #d4edda;
            color: #155724;
        }
        
        .badge.warning {
            background-color: #fff3cd;
            color: #856404;
        }
        
        .badge.danger {
            background-color: #f8d7da;
            color: #721c24;
        }
        
        .badge.info {
            background-color: #d1ecf1;
            color: #0c5460;
        }
        
        .code-block {
            background-color: #2d3748;
            color: #e2e8f0;
            padding: 15px;
            border-radius: 6px;
            font-family: 'Courier New', monospace;
            overflow-x: auto;
            margin: 15px 0;
        }
        
        .footer {
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #eaeaea;
            color: #7f8c8d;
            font-size: 0.9em;
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 15px;
            }
            
            .stats-grid {
                grid-template-columns: 1fr;
            }
            
            table {
                display: block;
                overflow-x: auto;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📊 Binary Analysis Report</h1>
            <div class="meta">
                Generated: {{ report.analysis_timestamp }} | 
                Tool Version: {{ report.tool_version }}
            </div>
        </div>
        
        {% if report.summary %}
        <div class="section">
            <h2><i>📈</i> Summary</h2>
            <div class="stats-grid">
                {% for key, value in report.summary.items() %}
                    {% if key not in ['entropy', 'estimated_code_size'] %}
                    <div class="stat-card">
                        <div class="stat-label">{{ key.replace('_', ' ').title() }}</div>
                        <div class="stat-value">{{ value }}</div>
                    </div>
                    {% endif %}
                {% endfor %}
            </div>
            
            {% if report.summary.entropy %}
            <div class="card">
                <h3>Entropy Analysis</h3>
                <p>Overall Entropy: <strong>{{ "%.3f"|format(report.summary.entropy.overall) }}</strong></p>
                <p>High Entropy: 
                    <span class="badge {{ 'danger' if report.summary.entropy.high_entropy else 'success' }}">
                        {{ 'Yes' if report.summary.entropy.high_entropy else 'No' }}
                    </span>
                </p>
            </div>
            {% endif %}
        </div>
        {% endif %}
        
        {% set binary_info = report.analysis_results.get('binary_info', {}) %}
        
        {% if binary_info %}
        <div class="section">
            <h2><i>🔍</i> Binary Information</h2>
            
            <div class="card">
                <h3>General Information</h3>
                <p><strong>Architecture:</strong> {{ binary_info.architecture }}</p>
                <p><strong>Entry Point:</strong> 0x{{ "%x"|format(binary_info.entry_point) }}</p>
                <p><strong>Analysis Tools Used:</strong> 
                    {% if binary_info.metadata.analyzed_with_capstone %}Capstone {% endif %}
                    {% if binary_info.metadata.analyzed_with_lief %}LIEF {% endif %}
                    {% if binary_info.metadata.analyzed_with_ghidra %}Ghidra {% endif %}
                </p>
            </div>
            
            {% if binary_info.sections %}
            <div class="card">
                <h3>Sections ({{ binary_info.sections|length }})</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>Address</th>
                            <th>Size</th>
                            <th>Executable</th>
                            <th>Entropy</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for section in binary_info.sections %}
                        <tr>
                            <td><code>{{ section.name }}</code></td>
                            <td>0x{{ "%x"|format(section.address) }}</td>
                            <td>{{ section.size }} bytes</td>
                            <td>
                                <span class="badge {{ 'success' if section.is_executable else 'info' }}">
                                    {{ 'Yes' if section.is_executable else 'No' }}
                                </span>
                            </td>
                            <td>{{ "%.3f"|format(section.entropy) }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            {% endif %}
            
            {% if binary_info.functions %}
            <div class="card">
                <h3>Functions ({{ binary_info.functions|length }})</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>Address</th>
                            <th>Size</th>
                            <th>Instructions</th>
                            <th>Exported</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for func in binary_info.functions[:10] %}
                        <tr>
                            <td><code>{{ func.name }}</code></td>
                            <td>0x{{ "%x"|format(func.address) }}</td>
                            <td>{{ func.size }} bytes</td>
                            <td>{{ func.instructions|length }}</td>
                            <td>
                                <span class="badge {{ 'success' if func.is_exported else 'info' }}">
                                    {{ 'Yes' if func.is_exported else 'No' }}
                                </span>
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
                {% if binary_info.functions|length > 10 %}
                <p style="margin-top: 10px; color: #7f8c8d;">
                    ... and {{ binary_info.functions|length - 10 }} more functions
                </p>
                {% endif %}
            </div>
            {% endif %}
            
            {% if binary_info.imports %}
            <div class="card">
                <h3>Imports ({{ binary_info.imports|length }})</h3>
                <table>
                    <thead>
                        <tr>
                            <th>DLL</th>
                            <th>Function</th>
                            <th>Ordinal</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for imp in binary_info.imports[:15] %}
                        <tr>
                            <td><code>{{ imp.dll }}</code></td>
                            <td><code>{{ imp.function }}</code></td>
                            <td>{% if imp.ordinal %}{{ imp.ordinal }}{% else %}-{% endif %}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
                {% if binary_info.imports|length > 15 %}
                <p style="margin-top: 10px; color: #7f8c8d;">
                    ... and {{ binary_info.imports|length - 15 }} more imports
                </p>
                {% endif %}
            </div>
            {% endif %}
            
            {% if binary_info.strings %}
            <div class="card">
                <h3>Extracted Strings ({{ binary_info.strings|length }})</h3>
                <div class="code-block">
                    {% for string in binary_info.strings[:20] %}
                    0x{{ "%x"|format(string.address) }}: {{ string.string|e }}<br>
                    {% endfor %}
                    {% if binary_info.strings|length > 20 %}
                    <br>... and {{ binary_info.strings|length - 20 }} more strings
                    {% endif %}
                </div>
            </div>
            {% endif %}
        </div>
        {% endif %}
        
        {% if report.analysis_results.get('assembly_info') %}
        <div class="section">
            <h2><i>⚙️</i> .NET Assembly Information</h2>
            
            {% set assembly_info = report.analysis_results.assembly_info %}
            
            <div class="card">
                <h3>Assembly Details</h3>
                <p><strong>Name:</strong> {{ assembly_info.name }}</p>
                <p><strong>Version:</strong> {{ assembly_info.version }}</p>
                <p><strong>Architecture:</strong> {{ assembly_info.architecture }}</p>
                <p><strong>Target Framework:</strong> {{ assembly_info.target_framework }}</p>
                <p><strong>Types:</strong> {{ assembly_info.types|length }}</p>
                <p><strong>Entry Point:</strong> {{ assembly_info.entry_point or 'None' }}</p>
            </div>
            
            {% if assembly_info.types %}
            <div class="card">
                <h3>Types ({{ assembly_info.types|length }})</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>Namespace</th>
                            <th>Methods</th>
                            <th>Fields</th>
                            <th>Properties</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for type in assembly_info.types[:10] %}
                        <tr>
                            <td><code>{{ type.name }}</code></td>
                            <td><code>{{ type.namespace }}</code></td>
                            <td>{{ type.methods|length }}</td>
                            <td>{{ type.fields|length }}</td>
                            <td>{{ type.properties|length }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
                {% if assembly_info.types|length > 10 %}
                <p style="margin-top: 10px; color: #7f8c8d;">
                    ... and {{ assembly_info.types|length - 10 }} more types
                </p>
                {% endif %}
            </div>
            {% endif %}
        </div>
        {% endif %}
        
        <div class="footer">
            <p>Report generated by Binary Deobfuscator Tool</p>
            <p>For security analysis and educational purposes only</p>
        </div>
    </div>
</body>
</html>"""