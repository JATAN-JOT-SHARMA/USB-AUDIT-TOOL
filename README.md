# 🔐 USB Security Scanner Tool

![USB Security Scanner](https://img.shields.io/badge/Cybersecurity-USB%20Protection-blue)
![Python](https://img.shields.io/badge/Python-3.x-yellow)
![License](https://img.shields.io/badge/License-MIT-green)

## 📌 Overview

**USB Security Scanner** is a cybersecurity utility designed to protect systems from malicious USB devices, infected files, and unauthorized removable storage access.

The tool automatically detects USB insertion, scans connected devices for suspicious files, identifies potential malware threats, and provides security recommendations to the user.

It is built for cybersecurity learning, endpoint protection research, and security awareness purposes.

---

# 🚀 Features

## 🔍 USB Device Monitoring
- Automatically detects USB device connections
- Tracks removable storage activity
- Displays connected USB information

## 🛡️ Malware & Threat Scanning
- Scans USB drives for suspicious files
- Detects potentially harmful extensions
- Identifies autorun-based threats
- Checks hidden and suspicious files

## 🚨 Real-Time Alerts
- Provides security warnings
- Shows threat severity levels
- Notifies users about risky USB activity

## 📂 File Analysis
- File extension analysis
- Suspicious filename detection
- Hidden file detection
- Hash-based file identification

## 🔒 USB Protection Features
- USB activity logging
- Scan reports generation
- Quarantine suspicious files
- Security recommendations

## 📊 Security Reports
- Generates detailed scan reports
- Stores scan history
- Provides threat summaries

---

# 🖥️ Screenshots

(Add your screenshots here)

```
screenshots/
 ├── dashboard.png
 ├── usb_scan.png
 └── report.png
```

---

# 🏗️ Project Architecture

```
USB Scanner Tool

        |
        |
 USB Detection Module
        |
        |
 File Scanner Engine
        |
        |
 Threat Analysis Module
        |
        |
 Report Generator
        |
        |
 User Interface
```

---

# 🛠️ Technologies Used

- Python 3
- Tkinter / CustomTkinter (GUI)
- OS Module
- Hashlib
- File System Monitoring
- Malware Detection Logic
- JSON Reporting

---

# 📋 Requirements

Install required packages:

```bash
pip install -r requirements.txt
```

Example requirements:

```
customtkinter
psutil
pillow
python-magic
requests
```

---

# ⚙️ Installation

## Clone Repository

```bash
git clone https://github.com/yourusername/USB-Security-Scanner.git
```

Move into project directory:

```bash
cd USB-Security-Scanner
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

# ▶️ Running the Tool

Run:

```bash
python main.py
```

---

# 🪟 Windows EXE Build

Install PyInstaller:

```bash
pip install pyinstaller
```

Create executable:

```bash
pyinstaller --onefile --windowed main.py
```

The executable will be created inside:

```
dist/
```

---

# 🔄 Workflow

```
USB Inserted
      |
      ↓
Device Detection
      |
      ↓
File Enumeration
      |
      ↓
Threat Analysis
      |
      ↓
Suspicious File Detection
      |
      ↓
Alert + Report Generation
```

---

# 🔥 Future Enhancements

- AI-based malware classification
- Cloud threat intelligence integration
- VirusTotal API integration
- Automatic USB blocking
- Real-time background monitoring service
- Ransomware behavior detection
- Machine learning threat prediction
- Network-based threat intelligence

---

# ⚠️ Disclaimer

This project is created for **educational and cybersecurity research purposes only**.

Do not use this tool to scan systems or devices without proper authorization.

The developer is not responsible for misuse of this software.

---

# 👨‍💻 Developer

**Jatanjot Sharma**

Cybersecurity | Python | AI/ML | Security Tools Development

---

# 📜 License

This project is licensed under the MIT License.
