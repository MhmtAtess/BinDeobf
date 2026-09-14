# Installation & Configuration Guide

## 📋 Table of Contents
1. [System Requirements](#system-requirements)
2. [Quick Installation](#quick-installation)
3. [Detailed Installation](#detailed-installation)
4. [Configuration](#configuration)
5. [Advanced Setup](#advanced-setup)
6. [Troubleshooting](#troubleshooting)
7. [Upgrading](#upgrading)

## System Requirements

### Minimum Requirements
- **Operating System**: Windows 10+, Linux (Ubuntu 18.04+), macOS 10.15+
- **Python**: 3.9 or higher
- **RAM**: 4 GB minimum (8 GB recommended for large files)
- **Storage**: 500 MB free space
- **Permissions**: Read access for binary files, write access for output directories

### Recommended Requirements
- **CPU**: 4+ cores for faster analysis
- **RAM**: 16 GB for analyzing large binaries (>100 MB)
- **Storage**: SSD for better I/O performance
- **Network**: For API usage and optional threat intelligence integration

### Dependencies Overview

| Dependency | Purpose | Required |
|------------|---------|----------|
| Python 3.9+ | Runtime environment | ✅ Required |
| pip | Package manager | ✅ Required |
| pefile | PE file parsing | ✅ Required |
| lief | Cross-platform binary parsing | ✅ Required |
| dnlib | .NET assembly analysis | ✅ Required |
| capstone | Disassembly engine | ✅ Required |
| typer | CLI framework | ✅ Required |
| fastapi | REST API framework | ✅ Required |
| rich | Terminal formatting | ✅ Required |
| pythonnet | .NET interop | ⚠️ Optional (.NET decompilation) |
| pyghidra | Ghidra integration | ⚠️ Optional (Advanced decompilation) |
| rzpipe | Rizin/Cutter integration | ⚠️ Optional (Alternative analysis) |

## Quick Installation

### Windows
```powershell
# 1. Clone repository
git clone https://github.com/yourusername/binary-deobfuscator.git
cd binary-deobfuscator

# 2. Install Python (if not installed)
# Download from https://www.python.org/downloads/
# Make sure to check "Add Python to PATH"

# 3. Install dependencies
pip install -r requirements.txt

# 4. Verify installation
python cli.py version
```

### Linux
```bash
# 1. Clone repository
git clone https://github.com/yourusername/binary-deobfuscator.git
cd binary-deobfuscator

# 2. Install Python (if not installed)
sudo apt update
sudo apt install python3 python3-pip python3-venv

# 3. Create virtual environment
python3 -m venv venv
source venv/bin/activate

# 4. Install dependencies
pip install -r requirements.txt

# 5. Verify installation
python cli.py version
```

### macOS
```bash
# 1. Clone repository
git clone https://github.com/yourusername/binary-deobfuscator.git
cd binary-deobfuscator

# 2. Install Python (if not installed)
brew install python

# 3. Create virtual environment
python3 -m venv venv
source venv/bin/activate

# 4. Install dependencies
pip install -r requirements.txt

# 5. Verify installation
python cli.py version
```

## Detailed Installation

### Step 1: Python Environment Setup

#### Windows with PowerShell
```powershell
# Check Python version
python --version

# If Python is not installed, download and install from:
# https://www.python.org/downloads/

# Upgrade pip
python -m pip install --upgrade pip

# Install virtual environment (optional but recommended)
pip install virtualenv

# Create virtual environment
virtualenv venv

# Activate virtual environment
venv\Scripts\activate
```

#### Linux/macOS
```bash
# Check Python version
python3 --version

# Install pip if not present
sudo apt install python3-pip  # Ubuntu/Debian
# or
brew install python3          # macOS

# Upgrade pip
pip3 install --upgrade pip

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate
```

### Step 2: Install Core Dependencies

#### Basic Installation
```bash
# Install from requirements.txt
pip install -r requirements.txt
```

#### Manual Installation (if needed)
```bash
# Core binary analysis
pip install pefile==2023.2.7
pip install lief==0.14.1
pip install python-magic==0.4.27

# .NET analysis
pip install dnlib==3.6.0
pip install pythonnet==3.0.3

# Disassembly
pip install capstone==5.0.1
pip install keystone-engine==0.9.2

# CLI and API
pip install typer==0.12.3
pip install fastapi==0.115.0
pip install uvicorn[standard]==0.30.5
pip install rich==13.9.4

# Utilities
pip install click==8.1.7
pip install pydantic==2.8.2
pip install pyyaml==6.0.1
pip install colorama==0.4.6
```

### Step 3: Install Optional Dependencies

#### .NET Framework (Windows)
For full .NET decompilation support:

```powershell
# Install .NET Framework (if not present)
# Download from: https://dotnet.microsoft.com/download

# Install pythonnet with specific configuration
pip install pythonnet==3.0.3

# For advanced .NET decompilation, install ILSpy/ICSharpCode.Decompiler
# This requires additional setup - see Advanced Setup section
```

#### Ghidra Integration
```bash
# 1. Install Java (required for Ghidra)
# Ubuntu/Debian:
sudo apt install openjdk-11-jdk

# macOS:
brew install openjdk@11

# Windows: Download from https://adoptium.net/

# 2. Install Ghidra
# Download from: https://ghidra-sre.org/
# Extract to a directory, e.g., /opt/ghidra

# 3. Install PyGhidra
pip install pyghidra

# 4. Set up Ghidra path
export GHIDRA_INSTALL_DIR=/path/to/ghidra
# Add to ~/.bashrc or ~/.zshrc for persistence
```

#### Rizin/Cutter Integration
```bash
# Ubuntu/Debian
sudo apt install rizin rizin-cutter rzpipe

# macOS
brew install rizin rzpipe

# Install Python bindings
pip install rzpipe
```

### Step 4: Verify Installation

#### Test CLI
```bash
# Check version
python cli.py version

# Test basic detection on a sample file
python cli.py detect /path/to/any/executable

# Run self-test (if available)
python -m pytest tests/ -v
```

#### Test API
```bash
# Start API server
python api.py --host 127.0.0.1 --port 8000 &

# Test API health
curl http://127.0.0.1:8000/api/health

# Test file upload (using a test file)
curl -X POST -F "file=@/path/to/test.exe" http://127.0.0.1:8000/api/upload/detect
```

## Configuration

### Environment Variables

Create a `.env` file in the project root:

```env
# API Configuration
BINARY_API_HOST=0.0.0.0
BINARY_API_PORT=8000
BINARY_API_WORKERS=4
BINARY_API_RELOAD=false  # Set to true for development

# Analysis Configuration
BINARY_MAX_FILE_SIZE=104857600  # 100MB max file size
BINARY_TEMP_DIR=/tmp/binary_analysis
BINARY_LOG_LEVEL=INFO

# Security Configuration
BINARY_ALLOWED_EXTENSIONS=.exe,.dll,.sys,.bin,.so,.elf,.com
BINARY_DISABLE_EXECUTION=true

# Threat Intelligence (Optional)
VIRUSTOTAL_API_KEY=your_virustotal_api_key
HYBRIDANALYSIS_API_KEY=your_hybridanalysis_api_key
```

### Configuration File

Create `config.yaml` in the project root:

```yaml
# Binary Deobfuscator Configuration

api:
  host: "0.0.0.0"
  port: 8000
  workers: 4
  reload: false
  cors_origins:
    - "http://localhost:3000"
    - "http://127.0.0.1:3000"

analysis:
  max_file_size: 104857600  # 100MB
  timeout_seconds: 300
  temp_directory: "/tmp/binary_deobfuscator"
  cleanup_after_hours: 24
  
  # File type restrictions
  allowed_extensions:
    - ".exe"
    - ".dll"
    - ".sys"
    - ".bin"
    - ".so"
    - ".elf"
    - ".com"
    - ".ocx"
    - ".cpl"
  
  # Analysis options
  extract_strings: true
  min_string_length: 4
  calculate_entropy: true
  detect_packed: true

decompilation:
  dotnet:
    enabled: true
    decompiler: "dnlib"  # or "icsharpcode"
    generate_projects: true
    
  native:
    enabled: true
    disassembler: "capstone"  # or "zydis"
    generate_pseudocode: true

logging:
  level: "INFO"
  file: "binary_deobfuscator.log"
  max_size_mb: 10
  backup_count: 5

security:
  disable_execution: true
  sandbox_mode: true
  max_concurrent_analyses: 10
  
  # Threat intelligence integration
  threat_intel:
    virustotal:
      enabled: false
      api_key: ""
      timeout: 10
      
    hybridanalysis:
      enabled: false
      api_key: ""
      timeout: 10

integration:
  siem:
    enabled: false
    endpoint: ""
    api_key: ""
    
  docker:
    enabled: false
    image: "binary-deobfuscator"
    port: 8000
```

### Docker Configuration

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  binary-deobfuscator:
    build: .
    container_name: binary-deobfuscator
    restart: unless-stopped
    ports:
      - "8000:8000"
    volumes:
      - ./data:/data
      - ./config.yaml:/app/config.yaml
      - ./logs:/app/logs
    environment:
      - BINARY_API_HOST=0.0.0.0
      - BINARY_API_PORT=8000
      - BINARY_LOG_LEVEL=INFO
      - BINARY_TEMP_DIR=/tmp
    ulimits:
      nproc: 65535
      nofile:
        soft: 20000
        hard: 40000
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/api/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
```

### System Service Configuration

#### Linux Systemd Service
Create `/etc/systemd/system/binary-deobfuscator.service`:

```ini
[Unit]
Description=Binary Deobfuscator API Service
After=network.target
Requires=network.target

[Service]
Type=simple
User=binaryuser
Group=binarygroup
WorkingDirectory=/opt/binary-deobfuscator
Environment="PATH=/opt/binary-deobfuscator/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Environment="PYTHONPATH=/opt/binary-deobfuscator"
ExecStart=/opt/binary-deobfuscator/venv/bin/python api.py --host 0.0.0.0 --port 8000
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=binary-deobfuscator
LimitNOFILE=65536
LimitNPROC=65536

[Install]
WantedBy=multi-user.target
```

Setup commands:
```bash
# Create system user
sudo useradd -r -s /bin/false binaryuser
sudo groupadd binarygroup
sudo usermod -a -G binarygroup binaryuser

# Set permissions
sudo chown -R binaryuser:binarygroup /opt/binary-deobfuscator
sudo chmod -R 750 /opt/binary-deobfuscator

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable binary-deobfuscator
sudo systemctl start binary-deobfuscator
sudo systemctl status binary-deobfuscator
```

#### Windows Service
Create `install_windows_service.py`:

```python
import win32serviceutil
import win32service
import win32event
import servicemanager
import sys
import os

class BinaryDeobfuscatorService(win32serviceutil.ServiceFramework):
    _svc_name_ = "BinaryDeobfuscator"
    _svc_display_name_ = "Binary Deobfuscator API Service"
    _svc_description_ = "Provides binary analysis and decompilation services"
    
    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.is_running = True
    
    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)
        self.is_running = False
    
    def SvcDoRun(self):
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, '')
        )
        
        # Change to script directory
        script_dir = os.path.dirname(os.path.abspath(__file__))
        os.chdir(script_dir)
        
        # Start the API server
        import subprocess
        self.process = subprocess.Popen([
            "python", "api.py", "--host", "0.0.0.0", "--port", "8000"
        ])
        
        # Wait for stop signal
        win32event.WaitForSingleObject(self.hWaitStop, win32event.INFINITE)
        self.process.terminate()
        self.process.wait()

if __name__ == '__main__':
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(BinaryDeobfuscatorService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(BinaryDeobfuscatorService)
```

Installation:
```powershell
# Install pywin32
pip install pywin32

# Install service
python install_windows_service.py install

# Start service
python install_windows_service.py start

# Check status
python install_windows_service.py status
```

## Advanced Setup

### Database Integration

For storing analysis results:

```python
# database_config.py
import sqlite3
import json
from datetime import datetime

class AnalysisDatabase:
    def __init__(self, db_path="analyses.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS analyses (
                id TEXT PRIMARY KEY,
                filename TEXT,
                file_hash TEXT,
                analysis_type TEXT,
                results_json TEXT,
                timestamp DATETIME,
                user TEXT,
                tags TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS indicators (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id TEXT,
                indicator_type TEXT,
                indicator_value TEXT,
                confidence REAL,
                FOREIGN KEY (analysis_id) REFERENCES analyses (id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def save_analysis(self, analysis_id, filename, file_hash, analysis_type, results, user="system", tags=None):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO analyses (id, filename, file_hash, analysis_type, results_json, timestamp, user, tags)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            analysis_id,
            filename,
            file_hash,
            analysis_type,
            json.dumps(results),
            datetime.now().isoformat(),
            user,
            json.dumps(tags) if tags else None
        ))
        
        conn.commit()
        conn.close()
```

### Load Balancer Configuration

For high-traffic deployments:

```nginx
# nginx configuration
upstream binary_deobfuscator {
    least_conn;
    server 127.0.0.1:8000 max_fails=3 fail_timeout=30s;
    server 127.0.0.1:8001 max_fails=3 fail_timeout=30s;
    server 127.0.0.1:8002 max_fails=3 fail_timeout=30s;
    keepalive 32;
}

server {
    listen 80;
    server_name binary-api.example.com;
    
    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    
    # File upload size limit
    client_max_body_size 100M;
    
    location / {
        proxy_pass http://binary_deobfuscator;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 300s;
    }
    
    # Health check endpoint
    location /api/health {
        access_log off;
        proxy_pass http://binary_deobfuscator;
    }
}
```

### Monitoring Setup

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'binary-deobfuscator'
    static_configs:
      - targets: ['localhost:8000']
    metrics_path: '/metrics'
    
# Create metrics endpoint in api.py
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST

# Define metrics
ANALYSIS_REQUESTS = Counter('analysis_requests_total', 'Total analysis requests')
ANALYSIS_DURATION = Histogram('analysis_duration_seconds', 'Analysis duration in seconds')

@app.get("/metrics")
async def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
```

## Troubleshooting

### Common Issues

#### Issue: "ModuleNotFoundError: No module named 'pefile'"
**Solution**: Install dependencies from requirements.txt
```bash
pip install -r requirements.txt
```

#### Issue: "Failed to load .NET assembly"
**Solution**: Check if file is a valid .NET assembly and .NET Framework is installed
```powershell
# Check .NET installation
dotnet --info

# Install .NET Framework if needed
# https://dotnet.microsoft.com/download/dotnet-framework
```

#### Issue: "Capstone disassembly failed"
**Solution**: Install capstone with proper architecture support
```bash
# Reinstall capstone
pip uninstall capstone
pip install capstone --no-binary capstone
```

#### Issue: "API server not starting on Windows"
**Solution**: Check port availability and firewall settings
```powershell
# Check if port 8000 is in use
netstat -ano | findstr :8000

# Open firewall port
New-NetFirewallRule -DisplayName "Binary Deobfuscator API" -Direction Inbound -Protocol TCP -LocalPort 8000 -Action Allow
```

#### Issue: "Memory error when analyzing large files"
**Solution**: Increase memory limits and use streaming analysis
```bash
# Set environment variable for larger files
export BINARY_MAX_MEMORY=4096  # MB

# Use streaming mode
python cli.py analyze large_file.exe --stream --output ./analysis
```

### Debug Mode

Enable detailed logging for troubleshooting:

```bash
# Set debug environment variable
export BINARY_DEBUG=1
export BINARY_LOG_LEVEL=DEBUG

# Run with verbose output
python cli.py analyze file.exe --verbose

# Check logs
tail -f binary_deobfuscator.log
```

### Performance Tuning

For large-scale deployments:

```bash
# Optimize Python for performance
export PYTHONUNBUFFERED=1
export PYTHONHASHSEED=0

# Increase file descriptors
ulimit -n 65536

# Use performance-optimized dependencies
pip install --no-binary :all: capstone
pip install --no-binary :all: lief
```

## Upgrading

### Regular Updates
```bash
# Update from git
git pull origin main

# Update dependencies
pip install --upgrade -r requirements.txt

# Clear cache
rm -rf __pycache__/
rm -rf *.pyc

# Restart services
sudo systemctl restart binary-deobfuscator
```

### Version Migration

When upgrading between major versions:

1. **Backup configuration and data**
   ```bash
   cp config.yaml config.yaml.backup
   cp -r data/ data_backup/
   ```

2. **Check breaking changes**
   ```bash
   git log --oneline v1.0.0..HEAD --grep="BREAKING"
   ```

3. **Update configuration files**
   ```bash
   # Compare and merge config changes
   diff config.yaml.example config.yaml
   ```

4. **Test upgrade**
   ```bash
   python cli.py version
   python cli.py detect test_file.exe
   ```

### Database Migration

If using database integration:

```python
# migration_script.py
import sqlite3
import json

def migrate_database(old_db, new_db):
    old_conn = sqlite3.connect(old_db)
    new_conn = sqlite3.connect(new_db)
    
    # Copy analyses table
    old_analyses = old_conn.execute("SELECT * FROM analyses").fetchall()
    
    for analysis in old_analyses:
        # Transform data if needed
        new_conn.execute("""
            INSERT INTO analyses (id, filename, file_hash, analysis_type, results_json, timestamp, user, tags)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, analysis)
    
    new_conn.commit()
    old_conn.close()
    new_conn.close()
```

This guide provides comprehensive installation and configuration instructions for the Binary Deobfuscator tool. For additional help, refer to the [README.md](README.md) or open an issue on the GitHub repository.