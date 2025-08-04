
# 🔐 SniffScan – Lightweight PCAP Traffic Analyzer

[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Maintained](https://img.shields.io/badge/status-maintained-brightgreen.svg)]()

**NetSleuth** is a lightweight command-line tool built in Python for offline analysis of `.pcap` files. It detects potentially sensitive or malicious traffic using **keyword-based payload inspection** and **IP address matching** against a threat list.

---

## 🔧 Features

- 📁 Analyze any `.pcap` file with Scapy
- 🧠 Detect sensitive keywords in packet payloads (e.g. `password`, `admin`)
- 🚨 Flag known suspicious IP addresses
- 📝 Log flagged traffic for later investigation
- 🔌 Easily extendable for forensic or educational use

---

## 📦 Installation

```bash
git clone https://github.com/yourusername/netsleuth.git
cd netsleuth
pip install -r requirements.txt
```

> Required packages: `scapy`, `colorama`

---

## 🚀 Usage

```bash
python netwatcher.py --pcap sample.pcap --keywords password,admin --log output/suspicious.log
```

### Optional Flags:
- `--keywords`: Comma-separated list of strings to match in payloads
- `--log`: Output path for suspicious log entries

---

## 🧪 Sample Input

You can download example `.pcap` files from [Wireshark SampleCaptures](https://wiki.wireshark.org/SampleCaptures).

Place the file (e.g. `http.cap`) in the project folder and run NetSleuth on it.

---

## 📂 Project Structure

```
netsleuth/
├── netwatcher.py
├── suspicious_ips.txt
├── sample.pcap  # (add your own)
├── output/
│   └── suspicious.log
└── README.md
```

---

## 🛡️ Future Enhancements

- GeoIP tagging of flagged IPs
- VirusTotal API integration
- Real-time sniffing mode (for Linux with sudo)
- Web dashboard interface (Flask)

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---
