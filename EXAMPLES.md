# Binary Deobfuscator - Examples & Use Cases

This document provides practical examples and use cases for the Binary Deobfuscator tool.

## 📋 Table of Contents
1. [Basic Analysis Examples](#basic-analysis-examples)
2. [.NET Decompilation Scenarios](#net-decompilation-scenarios)
3. [Native Binary Analysis](#native-binary-analysis)
4. [Malware Analysis Workflow](#malware-analysis-workflow)
5. [Legacy Software Analysis](#legacy-software-analysis)
6. [API Automation Examples](#api-automation-examples)
7. [Integration Examples](#integration-examples)

## Basic Analysis Examples

### Example 1: Quick File Analysis
```bash
# Basic file detection
python cli.py detect suspicious_file.exe

# Detailed analysis with report
python cli.py analyze malware_sample.bin --output ./analysis --format html

# Check for .NET managed code
python cli.py detect application.dll --detailed
```

### Example 2: Batch Processing
```bash
#!/bin/bash
# Analyze multiple files in a directory
for file in ./samples/*; do
    echo "Analyzing $file..."
    python cli.py analyze "$file" --output "./reports/$(basename "$file")"
done
```

### Example 3: Extracting Security Indicators
```bash
# Extract all imports from a binary
python cli.py imports suspicious.exe --format json > imports.json

# Extract strings for threat intelligence
python cli.py strings malware.bin --min-length 8 --output iocs.txt

# Check for packed sections (high entropy)
python cli.py analyze packed_app.exe --detailed | grep -i entropy
```

## .NET Decompilation Scenarios

### Example 1: Full .NET Application Decompilation
```bash
# Decompile entire .NET application
python cli.py decompile MyApp.exe --output ./decompiled_source

# Generate detailed report
python cli.py analyze MyApp.exe --output ./reports --format html

# Extract specific types
python cli.py analyze MyApp.exe --detailed | grep -A 5 "Type:"
```

### Example 2: Library Analysis for Security Review
```bash
# Analyze third-party library
python cli.py analyze ThirdPartyLib.dll --output ./security_review

# Check for suspicious API calls
python cli.py imports ThirdPartyLib.dll | grep -i "crypt\|key\|secret"

# Extract embedded resources
python cli.py analyze ThirdPartyLib.dll --detailed | grep -i resource
```

### Example 3: Obfuscated .NET Binary Analysis
```bash
# Analyze obfuscated .NET binary
python cli.py analyze obfuscated_app.exe --output ./obfuscation_analysis

# Force decompilation even if detection fails
python cli.py decompile obfuscated_app.exe --output ./attempt_decompile --force

# Extract strings with different encodings
python cli.py strings obfuscated_app.exe --encoding utf16 --output encoded_strings.txt
```

## Native Binary Analysis

### Example 1: Windows Executable Analysis
```bash
# Analyze Windows PE file
python cli.py analyze windows_app.exe --output ./pe_analysis

# Extract disassembly of entry point
python cli.py analyze windows_app.exe --detailed | grep -A 20 "entry"

# Check for anti-debugging techniques
python cli.py strings windows_app.exe | grep -i "debug\|detect\|vmware\|virtualbox"
```

### Example 2: Linux ELF Analysis
```bash
# Analyze Linux ELF binary
python cli.py analyze linux_app --output ./elf_analysis

# Check for stripped symbols
python cli.py detect linux_app --detailed

# Extract system calls
python cli.py strings linux_app | grep -i "syscall\|int 0x80"
```

### Example 3: Driver Analysis
```bash
# Analyze Windows driver
python cli.py analyze driver.sys --output ./driver_analysis

# Check for kernel-mode APIs
python cli.py imports driver.sys | grep -i "ntoskrnl\|hal\|wdm"

# Extract IRP handlers and device names
python cli.py strings driver.sys --min-length 3 | grep -i "device\|driver\|\\\\.\\\\"
```

## Malware Analysis Workflow

### Example 1: Initial Triage
```bash
#!/bin/bash
# Malware triage script
MALWARE="malware_sample.exe"
OUTPUT_DIR="./malware_analysis_$(date +%Y%m%d_%H%M%S)"

mkdir -p "$OUTPUT_DIR"

echo "=== MALWARE TRIAGE REPORT ===" > "$OUTPUT_DIR/report.txt"
echo "File: $MALWARE" >> "$OUTPUT_DIR/report.txt"
echo "Analysis Date: $(date)" >> "$OUTPUT_DIR/report.txt"
echo "" >> "$OUTPUT_DIR/report.txt"

# 1. Basic detection
echo "=== BASIC DETECTION ===" >> "$OUTPUT_DIR/report.txt"
python cli.py detect "$MALWARE" >> "$OUTPUT_DIR/report.txt"
echo "" >> "$OUTPUT_DIR/report.txt"

# 2. Import analysis
echo "=== IMPORTED FUNCTIONS ===" >> "$OUTPUT_DIR/report.txt"
python cli.py imports "$MALWARE" --format table >> "$OUTPUT_DIR/report.txt"
echo "" >> "$OUTPUT_DIR/report.txt"

# 3. String extraction
echo "=== EXTRACTED STRINGS (min 8 chars) ===" >> "$OUTPUT_DIR/report.txt"
python cli.py strings "$MALWARE" --min-length 8 >> "$OUTPUT_DIR/strings.txt"
head -50 "$OUTPUT_DIR/strings.txt" >> "$OUTPUT_DIR/report.txt"
echo "" >> "$OUTPUT_DIR/report.txt"

# 4. Full analysis
python cli.py analyze "$MALWARE" --output "$OUTPUT_DIR" --format json

echo "Analysis complete. Results in: $OUTPUT_DIR"
```

### Example 2: Persistence Mechanism Detection
```bash
# Check for auto-start mechanisms
python cli.py strings malware.exe | grep -i \
  "runonce\|runservices\|startup\|autostart\|registry\|service"

# Check for scheduled tasks
python cli.py strings malware.exe | grep -i \
  "schtasks\|at\.exe\|taskeng\|taskschd"

# Check for service installation
python cli.py strings malware.exe | grep -i \
  "sc\.exe\|create service\|openscmanager"
```

### Example 3: Network Indicator Extraction
```bash
# Extract URLs and domains
python cli.py strings malware.bin | grep -E \
  "(http|https|ftp)://[a-zA-Z0-9./?=_%:-]*" > urls.txt

# Extract IP addresses
python cli.py strings malware.bin | grep -E \
  "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" > ips.txt

# Extract email addresses
python cli.py strings malware.bin | grep -E \
  "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b" > emails.txt
```

## Legacy Software Analysis

### Example 1: Old Windows Application
```bash
# Analyze legacy Windows application
python cli.py analyze legacy_app_2003.exe --output ./legacy_analysis

# Check for deprecated APIs
python cli.py imports legacy_app_2003.exe | grep -i \
  "wininet\|rasapi32\|odbc32\|oleaut32"

# Extract version information
python cli.py strings legacy_app_2003.exe | grep -i \
  "version\|copyright\|company\|product"
```

### Example 2: DOS Application Analysis
```bash
# Analyze DOS executable
python cli.py analyze dos_app.com --output ./dos_analysis

# Check for DOS interrupts
python cli.py strings dos_app.com | grep -i "int 21h\|int 10h\|int 13h"

# Extract text mode strings
python cli.py strings dos_app.com --encoding ascii > dos_strings.txt
```

### Example 3: Embedded System Binary
```bash
# Analyze embedded firmware
python cli.py analyze firmware.bin --output ./firmware_analysis

# Check for known RTOS strings
python cli.py strings firmware.bin | grep -i \
  "vxworks\|threadx\|freertos\|ucos"

# Extract configuration data
python cli.py strings firmware.bin --min-length 4 | grep -i \
  "config\|setting\|parameter\|baud\|port"
```

## API Automation Examples

### Example 1: Python Automation Script
```python
#!/usr/bin/env python3
"""
Automated binary analysis using the REST API
"""

import requests
import json
import os
from pathlib import Path

class BinaryAnalyzerAPI:
    def __init__(self, base_url="http://localhost:8000"):
        self.base_url = base_url
    
    def analyze_file(self, file_path, output_format="json"):
        """Upload and analyze a file"""
        with open(file_path, 'rb') as f:
            files = {'file': (Path(file_path).name, f)}
            data = {'output_format': output_format}
            
            response = requests.post(
                f"{self.base_url}/api/upload/analyze",
                files=files,
                data=data
            )
        
        return response.json()
    
    def extract_strings(self, file_path, min_length=4):
        """Extract strings from a file"""
        with open(file_path, 'rb') as f:
            files = {'file': (Path(file_path).name, f)}
            
            response = requests.post(
                f"{self.base_url}/api/upload/detect",
                files=files
            )
        
        # Get file info
        file_info = response.json()
        
        # Extract strings using local analysis
        import subprocess
        result = subprocess.run(
            ['python', 'cli.py', 'strings', file_path, 
             '--min-length', str(min_length), '--format', 'json'],
            capture_output=True,
            text=True
        )
        
        return json.loads(result.stdout)
    
    def batch_analyze(self, directory_path, output_dir="./reports"):
        """Analyze all binaries in a directory"""
        results = {}
        
        for file_path in Path(directory_path).glob("*"):
            if file_path.is_file():
                try:
                    print(f"Analyzing {file_path.name}...")
                    result = self.analyze_file(str(file_path))
                    results[file_path.name] = result
                    
                    # Save individual report
                    report_file = Path(output_dir) / f"{file_path.stem}_report.json"
                    report_file.parent.mkdir(parents=True, exist_ok=True)
                    
                    with open(report_file, 'w') as f:
                        json.dump(result, f, indent=2)
                        
                except Exception as e:
                    print(f"Error analyzing {file_path.name}: {e}")
        
        return results

# Usage
if __name__ == "__main__":
    analyzer = BinaryAnalyzerAPI()
    
    # Start API server if not running
    import subprocess
    import time
    
    try:
        # Check if server is running
        requests.get("http://localhost:8000/api/health", timeout=2)
        print("API server is already running")
    except:
        print("Starting API server...")
        # Start server in background
        subprocess.Popen(["python", "api.py", "--port", "8000"])
        time.sleep(5)  # Wait for server to start
    
    # Analyze a file
    result = analyzer.analyze_file("suspicious.exe")
    print(f"Analysis completed: {result.get('analysis_id')}")
    
    # Batch analysis
    if Path("./samples").exists():
        analyzer.batch_analyze("./samples", "./batch_reports")
```

### Example 2: Docker Integration
```dockerfile
# Dockerfile for Binary Deobfuscator API
FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    make \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create volume for analysis results
VOLUME ["/data"]

# Expose API port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8000/api/health')"

# Start API server
CMD ["python", "api.py", "--host", "0.0.0.0", "--port", "8000"]
```

```bash
# Build and run Docker container
docker build -t binary-deobfuscator .
docker run -d -p 8000:8000 -v ./data:/data binary-deobfuscator

# Use the API from host
curl http://localhost:8000/api/health
```

### Example 3: CI/CD Pipeline Integration
```yaml
# GitHub Actions workflow
name: Binary Security Analysis

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  analyze-binaries:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.9'
    
    - name: Install dependencies
      run: |
        pip install -r requirements.txt
        pip install -e .
    
    - name: Start API server
      run: |
        python api.py --host 0.0.0.0 --port 8000 &
        sleep 5
    
    - name: Analyze release binaries
      run: |
        mkdir -p analysis_reports
        
        # Find and analyze all binaries
        find . -name "*.exe" -o -name "*.dll" -o -name "*.so" | while read file; do
          echo "Analyzing $file"
          python cli.py analyze "$file" --output "./analysis_reports" --format json
        done
    
    - name: Check for security issues
      run: |
        # Check analysis reports for security issues
        python -c "
        import json
        import os
        
        security_issues = []
        
        for report_file in os.listdir('./analysis_reports'):
            if report_file.endswith('.json'):
                with open(f'./analysis_reports/{report_file}', 'r') as f:
                    report = json.load(f)
                
                # Check for high entropy (packed/obfuscated)
                entropy = report.get('summary', {}).get('entropy', {}).get('overall', 0)
                if entropy > 7.5:
                    security_issues.append(f'{report_file}: High entropy detected ({entropy})')
        
        if security_issues:
            print('Security issues found:')
            for issue in security_issues:
                print(f'  - {issue}')
            exit(1)
        else:
            print('No security issues detected')
        "
    
    - name: Upload analysis reports
      uses: actions/upload-artifact@v3
      with:
        name: binary-analysis-reports
        path: analysis_reports/
```

## Integration Examples

### Example 1: SIEM Integration
```python
"""
SIEM integration for binary analysis alerts
"""
import requests
import json
from datetime import datetime

class SIEMBinaryAnalyzer:
    def __init__(self, siem_url, api_key):
        self.siem_url = siem_url
        self.api_key = api_key
        self.binary_api = "http://localhost:8000"
    
    def analyze_suspicious_file(self, file_path, alert_id):
        """Analyze file from SIEM alert"""
        
        # Upload and analyze file
        with open(file_path, 'rb') as f:
            files = {'file': f}
            response = requests.post(
                f"{self.binary_api}/api/upload/analyze",
                files=files,
                data={'output_format': 'json'}
            )
        
        analysis_result = response.json()
        
        # Extract security indicators
        indicators = self.extract_indicators(analysis_result)
        
        # Send enriched alert back to SIEM
        enriched_alert = {
            'alert_id': alert_id,
            'analysis_timestamp': datetime.now().isoformat(),
            'file_info': {
                'path': file_path,
                'type': analysis_result.get('binary_info', {}).get('binary_type'),
                'architecture': analysis_result.get('binary_info', {}).get('architecture'),
                'managed': analysis_result.get('binary_info', {}).get('is_managed', False)
            },
            'security_indicators': indicators,
            'entropy_analysis': analysis_result.get('binary_info', {}).get('entropy_analysis', {}),
            'imports_count': len(analysis_result.get('binary_info', {}).get('imports', [])),
            'exports_count': len(analysis_result.get('binary_info', {}).get('exports', []))
        }
        
        # Send to SIEM
        siem_response = requests.post(
            f"{self.siem_url}/api/alerts/{alert_id}/enrich",
            json=enriched_alert,
            headers={'Authorization': f'Bearer {self.api_key}'}
        )
        
        return enriched_alert
    
    def extract_indicators(self, analysis_result):
        """Extract security indicators from analysis"""
        indicators = {
            'suspicious_imports': [],
            'suspicious_strings': [],
            'packer_indicators': [],
            'anti_debug_indicators': []
        }
        
        # Check imports for suspicious APIs
        suspicious_apis = [
            'VirtualAlloc', 'VirtualProtect', 'CreateRemoteThread',
            'WriteProcessMemory', 'LoadLibrary', 'GetProcAddress',
            'RegSetValue', 'CreateService', 'URLDownloadToFile'
        ]
        
        imports = analysis_result.get('binary_info', {}).get('imports', [])
        for imp in imports:
            if any(api.lower() in imp.get('function', '').lower() for api in suspicious_apis):
                indicators['suspicious_imports'].append(imp['function'])
        
        # Check for high entropy (packer indicator)
        entropy = analysis_result.get('binary_info', {}).get('entropy_analysis', {}).get('overall', 0)
        if entropy > 7.0:
            indicators['packer_indicators'].append(f'High entropy: {entropy:.2f}')
        
        return indicators
```

### Example 2: Threat Intelligence Platform Integration
```python
"""
Threat intelligence platform integration
"""
import hashlib
import requests
from typing import Dict, List

class ThreatIntelAnalyzer:
    def __init__(self, virustotal_api_key=None, hybridanalysis_api_key=None):
        self.vt_api_key = virustotal_api_key
        self.ha_api_key = hybridanalysis_api_key
        self.binary_api = "http://localhost:8000"
    
    def analyze_and_enrich(self, file_path: str) -> Dict:
        """Analyze file and enrich with threat intelligence"""
        
        # Calculate file hashes
        file_hashes = self.calculate_hashes(file_path)
        
        # Analyze with binary deobfuscator
        analysis_result = self.analyze_with_deobfuscator(file_path)
        
        # Enrich with threat intelligence
        threat_intel = {}
        
        if self.vt_api_key:
            threat_intel['virustotal'] = self.query_virustotal(file_hashes['sha256'])
        
        if self.ha_api_key:
            threat_intel['hybridanalysis'] = self.query_hybridanalysis(file_hashes['sha256'])
        
        # Combine results
        enriched_result = {
            'file_info': {
                'path': file_path,
                'hashes': file_hashes,
                'size': analysis_result.get('binary_info', {}).get('file_size')
            },
            'binary_analysis': analysis_result,
            'threat_intelligence': threat_intel,
            'risk_score': self.calculate_risk_score(analysis_result, threat_intel)
        }
        
        return enriched_result
    
    def calculate_hashes(self, file_path: str) -> Dict[str, str]:
        """Calculate file hashes"""
        hashes = {}
        
        with open(file_path, 'rb') as f:
            data = f.read()
            
            hashes['md5'] = hashlib.md5(data).hexdigest()
            hashes['sha1'] = hashlib.sha1(data).hexdigest()
            hashes['sha256'] = hashlib.sha256(data).hexdigest()
            hashes['sha512'] = hashlib.sha512(data).hexdigest()
        
        return hashes
    
    def analyze_with_deobfuscator(self, file_path: str) -> Dict:
        """Analyze file using binary deobfuscator API"""
        with open(file_path, 'rb') as f:
            files = {'file': f}
            response = requests.post(
                f"{self.binary_api}/api/upload/analyze",
                files=files,
                data={'output_format': 'json'}
            )
        
        return response.json()
    
    def query_virustotal(self, sha256_hash: str) -> Dict:
        """Query VirusTotal for file reputation"""
        if not self.vt_api_key:
            return {}
        
        url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
        headers = {"x-apikey": self.vt_api_key}
        
        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                return response.json()
        except:
            pass
        
        return {}
    
    def query_hybridanalysis(self, sha256_hash: str) -> Dict:
        """Query Hybrid Analysis for file reputation"""
        if not self.ha_api_key:
            return {}
        
        url = f"https://www.hybrid-analysis.com/api/v2/overview/{sha256_hash}"
        headers = {
            "api-key": self.ha_api_key,
            "user-agent": "BinaryDeobfuscator/1.0"
        }
        
        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                return response.json()
        except:
            pass
        
        return {}
    
    def calculate_risk_score(self, analysis_result: Dict, threat_intel: Dict) -> int:
        """Calculate risk score based on analysis and threat intelligence"""
        score = 0
        
        # Binary analysis factors
        entropy = analysis_result.get('binary_info', {}).get('entropy_analysis', {}).get('overall', 0)
        if entropy > 7.0:
            score += 30
        elif entropy > 6.0:
            score += 15
        
        # Suspicious imports
        imports = analysis_result.get('binary_info', {}).get('imports', [])
        suspicious_count = sum(1 for imp in imports if any(
            api in imp.get('function', '') for api in [
                'VirtualAlloc', 'CreateRemoteThread', 'WriteProcessMemory'
            ]
        ))
        score += suspicious_count * 10
        
        # Threat intelligence factors
        vt_result = threat_intel.get('virustotal', {})
        if vt_result:
            stats = vt_result.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            score += malicious * 5
        
        return min(score, 100)
```

These examples demonstrate the versatility of the Binary Deobfuscator tool for various security analysis, reverse engineering, and integration scenarios. The tool can be adapted to fit specific workflows and integrated with existing security infrastructure.