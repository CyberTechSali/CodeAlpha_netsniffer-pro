# 🛡️ NetSniffer Pro — Modern Network Analyzer

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/Scapy-2.5+-2C2D72?style=for-the-badge&logo=wireshark&logoColor=white" />
  <img src="https://img.shields.io/badge/CustomTkinter-5.0+-1F6FEB?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" />
</p>

<p align="center">
  <b>A modern, dark-themed network packet sniffer with real-time capture, protocol analysis, and export capabilities.</b>
</p>

<p align="center">
  <img src="screenshots/main_interface.png" alt="NetSniffer Pro Main Interface" width="850"/>
</p>

---

## 📋 Table of Contents

- [Features](#-features)
- [Architecture](#-architecture)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Usage](#-usage)
- [Supported Protocols](#-supported-protocols)
- [Export Options](#-export-options)
- [Screenshots](#-screenshots)
- [Project Structure](#-project-structure)
- [Contributing](#-contributing)
- [License](#-license)
- [Author](#-author)

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🎨 **Modern GUI** | Dark/Light themes with CustomTkinter (rounded widgets, glassmorphism cards) |
| 📡 **Real-Time Capture** | Live packet sniffing with instant table updates |
| 🔍 **Live Search** | Filter captured packets in real-time by IP, port, or protocol |
| 📊 **Stats Dashboard** | Color-coded stat cards showing protocol distribution at a glance |
| 🔎 **Deep Inspection** | Detailed packet info, hex dump, and payload entropy analysis |
| 💾 **CSV Export** | Export all captured data to spreadsheet-friendly CSV |
| 📦 **PCAP Export** | Save raw packets in Wireshark-compatible `.pcap` format |
| 🌐 **Multi-Protocol** | Detects TCP, UDP, ICMP, ARP, DNS, HTTP, and HTTPS/TLS traffic |
| 🖥️ **Cross-Platform** | Works on Linux (Kali), macOS, and Windows |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    NetSniffer Pro - GUI                      │
│  ┌──────────┐  ┌──────────────────────────────────────────┐ │
│  │ Sidebar  │  │            Main Area                     │ │
│  │          │  │  ┌──────────────────────────────────┐    │ │
│  │ • Iface  │  │  │     Stats Dashboard (9 cards)    │    │ │
│  │ • Filter │  │  └──────────────────────────────────┘    │ │
│  │ • Start  │  │  ┌──────────────────────────────────┐    │ │
│  │ • Stop   │  │  │     Live Search Bar              │    │ │
│  │ • Clear  │  │  └──────────────────────────────────┘    │ │
│  │ • Theme  │  │  ┌──────────────────────────────────┐    │ │
│  │          │  │  │     Packet Table (Treeview)       │    │ │
│  │          │  │  │     - No, Time, Src, Dst, Proto   │    │ │
│  │          │  │  └──────────────────────────────────┘    │ │
│  │          │  │  ┌──────────────────────────────────┐    │ │
│  │          │  │  │  Tabs: Info | Payload | Exports   │    │ │
│  │          │  │  └──────────────────────────────────┘    │ │
│  └──────────┘  └──────────────────────────────────────────┘ │
│  ┌──────────────────────────────────────────────────────┐   │
│  │               Status Bar                              │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘

┌─────────────────── Backend Flow ────────────────────────────┐
│                                                              │
│   scapy.sniff()  ──►  _classify()  ──►  process_packet()    │
│   (thread)             Protocol          Stats + Row         │
│                        Detection         Generation          │
│                                              │               │
│                                              ▼               │
│                                     GUI Update (after())     │
│                                     • Insert row             │
│                                     • Update stat cards      │
│                                     • Apply search filter    │
└──────────────────────────────────────────────────────────────┘
```

---

## 📦 Requirements

- **Python** 3.8 or higher
- **Operating System**: Linux (Kali recommended), macOS, or Windows
- **Privileges**: Administrator / root access required for raw packet capture

### Python Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `scapy` | ≥ 2.5 | Packet capture & dissection engine |
| `customtkinter` | ≥ 5.0 | Modern themed GUI widgets |

---

## 🚀 Installation

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/NetSniffer-Pro.git
cd NetSniffer-Pro
```

### 2. Create a virtual environment (recommended)

```bash
python3 -m venv venv
source venv/bin/activate        # Linux/macOS
# venv\Scripts\activate         # Windows
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

---

## ▶️ Usage

### Linux (Kali Linux)

```bash
sudo python3 sniffer.py
```

### Windows (Run as Administrator)

```powershell
python sniffer.py
```

### macOS

```bash
sudo python3 sniffer.py
```

> ⚠️ **Root/Admin privileges are required** because raw socket access is needed for packet capture.

---

## 🌐 Supported Protocols

| Protocol | Detection Method | Info Displayed |
|----------|-----------------|----------------|
| **TCP** | IP + TCP layer | Flags (SYN, ACK, FIN, RST...) |
| **UDP** | IP + UDP layer | Payload length |
| **ICMP** | IP + ICMP layer | Type & Code |
| **ARP** | ARP layer | who-has / is-at operations |
| **DNS** | UDP port 53 | Query/Response + domain name |
| **HTTP** | TCP port 80 | First line of HTTP request/response |
| **HTTPS/TLS** | TCP port 443 | Encrypted TLS/SSL indicator |

---

## 💾 Export Options

| Format | Extension | Use Case |
|--------|-----------|----------|
| **CSV** | `.csv` | Spreadsheet analysis, reporting |
| **PCAP** | `.pcap` | Open in Wireshark for deep analysis |

---

## 📸 Screenshots

<details>
<summary>Click to expand screenshots</summary>

### Dark Mode — Main Interface
<p align="center">
  <img src="screenshots/main_interface.png" alt="Main Interface" width="800"/>
</p>

### Packet Details & Hex Dump
<p align="center">
  <img src="screenshots/packet_details.png" alt="Packet Details" width="800"/>
</p>

### Exports & Session Summary
<p align="center">
  <img src="screenshots/exports_stats.png" alt="Exports & Stats" width="800"/>
</p>

</details>

> 💡 **Add your own screenshots** in the `screenshots/` folder and they will appear here.

---

## 📁 Project Structure

```
NetSniffer-Pro/
│
├── sniffer.py              # Main application (GUI + capture engine)
├── requirements.txt        # Python dependencies
├── LICENSE                 # MIT License
├── README.md               # This file
├── .gitignore              # Git ignore rules
│
└── screenshots/            # Screenshots for README
    ├── main_interface.png
    ├── packet_details.png
    └── exports_stats.png
```

---

## 🤝 Contributing

Contributions are welcome! Here's how:

1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature/my-feature`
3. **Commit** your changes: `git commit -m "Add my feature"`
4. **Push** to the branch: `git push origin feature/my-feature`
5. **Open** a Pull Request

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## 👤 Author

**CodeAlpha Cybersecurity Internship — Task 1**

> Built with ❤️ using Python, Scapy & CustomTkinter

---

<p align="center">
  <b>⭐ Star this repo if you found it useful!</b>
</p>
