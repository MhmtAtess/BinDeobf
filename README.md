# 🛡️ BinDeobf - Binary Deobfuscator & Analyzer

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688.svg)](https://fastapi.tiangolo.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey.svg)]()

> **[ 🇹🇷 Türkçe ](#-türkçe)** | **[ 🇬🇧 English ](#-english)**

---

# 🇹🇷 Türkçe

> **Gelişmiş İkili Dosya (Binary) Analiz, Deobfuskasyon ve Decompile Çerçevesi**
> 
> .NET derlemeleri, Native PE/ELF ikilileri ve karmaşık şifrelenmiş Python betikleri için kapsamlı analiz, tersine mühendislik ve otomatik raporlama aracı.

---

## 📋 İçindekiler
- [Özellikler](#-özellikler)
- [Kurulum](#-kurulum)
- [Kullanım Rehberi](#-kullanım-rehberi)
  - [CLI (Komut Satırı Arayüzü)](#1-cli-komut-satırı-arayüzü)
  - [REST API Sunucusu](#2-rest-api-sunucusu)
  - [AutoCrack Lisans Yama Aracı](#3-autocrack-lisans-yama-aracı)
- [Proje Mimarisi](#-proje-mimarisi)
- [Lisans](#-lisans)

---

## ✨ Özellikler

### 🔍 Otomatik İkili Dosya Tespiti ve Analizi
- **Header Analizi**: PE, ELF, Mach-O ve .NET CLR başlıklarının otomatik tespiti.
- **Mimari Tespiti**: x86, x64, ARM, ARM64 mimari belirleme.
- **Seksiyon & Entropi Analizi**: Seksiyon izinleri (R/W/X), RAW/Virtual boyut farkları ve entropi hesaplama (Packer/Protector tespiti).
- **Import / Export Çıkarımı**: DLL bağımlılıkları, içe/dışa aktarılan WinAPI fonksiyon listeleri.
- **String Çıkarıcı**: Otomatik ASCII ve UTF-16 metin ve URL çıkarma.

### ⚙️ .NET Decompilation (C# Kaynak Kod Çıkarma)
- **dnlib & ICSharpCode.Decompiler Entegrasyonu**: .NET Assembly yapısının analizi.
- **Tip & Metot Analizi**: Sınıflar, arayüzler, metotlar, alanlar ve özellikler.
- **C# Kod Üretimi**: Derlenmiş .NET ikililerini okunabilir C# koduna dönüştürme.

### 💻 Native İkili Analizi (C/C++ & Assembly)
- **Capstone Disassembly**: x86/x64 komut seti ayrıştırma.
- **Fonksiyon Prolog Tespiti**: Fonksiyon başlangıç noktalarının otomatik analizi.
- **Pseudocode Üretimi**: Disassembly verisinden C benzeri pseudocode üretimi.

### 🐍 Python Deobfuscator & Unpacker
- **Karmaşık Katman Çözme**: XOR, State Machine, Base64, Zlib ve Marshal katmanlarını otomatik çözme.
- **Gömülü Payload Çıkarma**: Betik içerisindeki gömülü `.pyd` / `.dll` dosyalarını tespit edip otomatik çıkarma ve decompile etme.

### 📊 Çoklu Raporlama & REST API
- **Formatlar**: JSON, YAML, HTML, Markdown ve CSV raporları.
- **REST API & Swagger UI**: FastAPI ile entegrasyon ve otomasyon.

---

## 🚀 Kurulum

### Gereksinimler
- **Python**: 3.9 veya daha üzeri
- **İşletim Sistemi**: Windows 10/11, Linux

### 1. Repoyu Klonlayın
```bash
git clone https://github.com/yourusername/BinDeobf.git
cd BinDeobf
```

### 2. Bağımlılıkları Yükleyin
```bash
pip install -r requirements.txt
```

*(İsteğe bağlı) Paketi geliştirici modunda yüklemek için:*
```bash
pip install -e .
```

---

## 💻 Kullanım Rehberi

### 1. CLI (Komut Satırı Arayüzü)

Tüm komutlar `cli.py` (veya kurduysanız `bindeobf`) üzerinden çalıştırılır.

#### 🟢 Dosya Decompile Etme (C# / Pseudocode / Python Source)
```bash
python cli.py decompile hedef_dosya.exe
```
*Çıktı varsayılan olarak `output/<dosya_adı>_decompiled/` dizinine kaydedilir.*

#### 🟢 Detaylı Analiz ve Rapor Oluşturma
```bash
# JSON formatında rapor (varsayılan)
python cli.py analyze hedef_dosya.exe

# HTML raporu oluşturma
python cli.py analyze hedef_dosya.exe -f html

# Tüm formatlarda rapor alma (JSON, YAML, HTML, Markdown)
python cli.py analyze hedef_dosya.exe -f all -o ./raporlar
```

#### 🟢 Metin ve String Çıkarma
```bash
# Dosyadaki metinleri çıkarma (varsayılan min 4 karakter)
python cli.py strings hedef_dosya.exe

# Minimum 6 karakterli stringleri çıkarma
python cli.py strings hedef_dosya.exe -m 6
```

#### 🟢 Hızlı Dosya ve Tip Tespiti
```bash
python cli.py detect hedef_dosya.exe --detailed
```

#### 🟢 İçe ve Dışa Aktarılan Fonksiyonlar (Imports / Exports)
```bash
# İçe aktarılan DLL ve fonksiyonlar
python cli.py imports hedef_dosya.exe

# Dışa aktarılan (Exported) fonksiyonlar
python cli.py exports hedef_dosya.exe
```

---

### 2. REST API Sunucusu

Web servis entegrasyonu ve otomasyon için FastAPI REST API sunucusunu başlatın:

```bash
python api.py
```
Sunucu başlatıldıktan sonra Swagger UI belgelendirmesine tarayıcınızdan ulaşabilirsiniz:
👉 **[http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)**

---

### 3. AutoCrack Lisans Yama Aracı

Statik PE dosyalarında lisans kontrol dallarını (JCC / JMP) tespit edip otomatik yamalamak (Patch) için:

```bash
# Yamalama analizi (Dry-run)
python autocrack.py hedef_dosya.exe --dry-run

# Otomatik yamalama uygula
python autocrack.py hedef_dosya.exe
```

---

## 📁 Proje Yapısı

```
BinDeobf/
├── core/                         # Çekirdek Analiz ve Decompile Modülleri
│   ├── detectors/                # Dosya ve Mimari Tespit Entegrasyonları
│   ├── decompilers/              # .NET, Native ve Python Deobfuscator
│   │   ├── dotnet_decompiler.py  # C# Decompiler (dnlib / ICSharpCode)
│   │   ├── native_analyzer.py    # Native Disassembly (Capstone)
│   │   ├── python_deobfuscator.py# Python Script & Unpacker
│   │   └── ast_restructurer.py   # AST Yapılandırma
│   └── exporters/                # Rapor Oluşturucu (JSON/HTML/MD)
├── api.py                        # FastAPI REST API Sunucusu
├── cli.py                        # Rich tabanlı CLI Arayüzü
├── autocrack.py                  # PE Otomatik Lisans Yama Aracı
├── setup.py                      # Paket Kurulum Betiği
├── requirements.txt              # Bağımlılık Listesi
├── .gitignore                    # Git Harici Tutma Dosyası
└── README.md                     # Proje Dokümantasyonu
```

---
---

# 🇬🇧 English

> **Advanced Binary Analysis, Deobfuscation & Decompilation Framework**
> 
> A comprehensive static analysis, reverse engineering, and automated reporting tool for .NET assemblies, Native PE/ELF binaries, and obfuscated Python scripts.

---

## 📋 Table of Contents
- [Features](#-features)
- [Installation](#-installation)
- [Usage Guide](#-usage-guide)
  - [CLI (Command Line Interface)](#1-cli-command-line-interface)
  - [REST API Server](#2-rest-api-server)
  - [AutoCrack Patching Tool](#3-autocrack-patching-tool)
- [Project Architecture](#-project-architecture)
- [License](#-license)

---

## ✨ Features

### 🔍 Automatic Binary Detection & Analysis
- **Header Analysis**: Automatic PE, ELF, Mach-O, and .NET CLR header detection.
- **Architecture Identification**: x86, x64, ARM, ARM64 architecture detection.
- **Section & Entropy Analysis**: Section permissions (R/W/X), RAW/Virtual size mismatch analysis, and entropy calculation for packer detection.
- **Import / Export Extraction**: Extract DLL dependencies, imported/exported WinAPI functions.
- **String Extractor**: Automatic ASCII and UTF-16 string and URL extraction.

### ⚙️ .NET Decompilation (C# Source Code Generation)
- **dnlib & ICSharpCode.Decompiler Integration**: Comprehensive .NET assembly metadata analysis.
- **Type & Method Analysis**: Analyze classes, interfaces, methods, fields, and properties.
- **C# Code Generation**: Decompile managed binaries back to clean C# source code.

### 💻 Native Binary Analysis (C/C++ & Assembly)
- **Capstone Disassembly**: x86/x64 instruction disassembly engine.
- **Function Prologue Detection**: Automatic function boundary detection.
- **Pseudocode Generation**: C-like pseudocode output generated from disassembly.

### 🐍 Python Deobfuscator & Unpacker
- **Multi-layer Unpacking**: Automatically unpack XOR, State Machine, Base64, Zlib, and Marshal obfuscation layers.
- **Embedded Payload Extraction**: Detect and extract embedded `.pyd` / `.dll` payloads and decompile them automatically.

### 📊 Multi-format Reporting & REST API
- **Export Formats**: JSON, YAML, HTML, Markdown, and CSV reports.
- **REST API & Swagger UI**: FastAPI integration for enterprise automation and pipeline integration.

---

## 🚀 Installation

### Requirements
- **Python**: 3.9 or higher
- **Operating System**: Windows 10/11, Linux

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/BinDeobf.git
cd BinDeobf
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

*(Optional) Install package in editable development mode:*
```bash
pip install -e .
```

---

## 💻 Usage Guide

### 1. CLI (Command Line Interface)

Execute commands via `cli.py` (or `bindeobf` if installed as a package).

#### 🟢 Decompile Binary (C# / Pseudocode / Python Source)
```bash
python cli.py decompile target_file.exe
```
*Output is automatically saved to `output/<filename>_decompiled/`.*

#### 🟢 Comprehensive Analysis & Report Generation
```bash
# Default JSON report
python cli.py analyze target_file.exe

# HTML visual report
python cli.py analyze target_file.exe -f html

# Export all report formats (JSON, YAML, HTML, Markdown)
python cli.py analyze target_file.exe -f all -o ./reports
```

#### 🟢 Extract Strings
```bash
# Extract ASCII/UTF-16 strings (default min-length: 4)
python cli.py strings target_file.exe

# Filter minimum length of 6 characters
python cli.py strings target_file.exe -m 6
```

#### 🟢 Fast Binary Detection
```bash
python cli.py detect target_file.exe --detailed
```

#### 🟢 Imported & Exported Functions
```bash
# List DLL imports
python cli.py imports target_file.exe

# List exported functions
python cli.py exports target_file.exe
```

---

### 2. REST API Server

Launch the FastAPI web API server for HTTP integration:

```bash
python api.py
```
Open Swagger UI documentation in your browser:
👉 **[http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)**

---

### 3. AutoCrack Patching Tool

Identify and patch conditional license check branches (JCC / JMP) in static PE binaries:

```bash
# Analyze patching targets (Dry-run mode)
python autocrack.py target_file.exe --dry-run

# Apply patch automatically
python autocrack.py target_file.exe
```

---

## 📁 Project Architecture

```
BinDeobf/
├── core/                         # Core Analysis & Decompilation Modules
│   ├── detectors/                # File Type & Architecture Detection
│   ├── decompilers/              # .NET, Native & Python Deobfuscators
│   │   ├── dotnet_decompiler.py  # C# Decompiler (dnlib / ICSharpCode)
│   │   ├── native_analyzer.py    # Native Disassembler (Capstone)
│   │   ├── python_deobfuscator.py# Python Script & Unpacker
│   │   └── ast_restructurer.py   # AST Structure Builder
│   └── exporters/                # Multi-format Report Generator (JSON/HTML/MD)
├── api.py                        # FastAPI REST API Server
├── cli.py                        # Rich CLI Interface
├── autocrack.py                  # PE Automated License Patcher
├── setup.py                      # Package Setup Script
├── requirements.txt              # Dependency Manifest
├── .gitignore                    # Git Ignore Configuration
└── README.md                     # Project Documentation
```

---

## 📜 License

This project is licensed under the **MIT License**.
