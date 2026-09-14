# 🛡️ BinDeobf - Binary Deobfuscator & Analyzer

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688.svg)](https://fastapi.tiangolo.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey.svg)]()

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

Tüm komutlar `cli.py` üzerinden çalıştırılır.

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

#### REST API Endpoint'leri:
- `POST /detect` - Yüklenen dosyanın tipini ve mimarisini tespit eder.
- `POST /analyze` - Statik analiz ve rapor üretimi.
- `POST /decompile` - Kaynak kod çıkarma.
- `GET /reports/{analysis_id}` - Oluşturulan analiz raporlarını indirir.

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

## 📜 Lisans

Bu proje **MIT Lisansı** altında lisanslanmıştır.
