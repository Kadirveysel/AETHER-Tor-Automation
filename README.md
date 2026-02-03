# 🛡️ AETHER-Tor-Automation

> **Dynamic Identity Shifting & Network Anonymity Tool**

AETHER is a high-performance, cross-platform network automation tool designed for security researchers and OSINT analysts. It interfaces directly with the Tor Control Port to manage identity rotation, featuring a "Session Killer" engine to ensure zero IP leaks.

![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python)
![Status](https://img.shields.io/badge/Status-Stable-green?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-orange?style=for-the-badge)

## 🚀 Features

* **Smart Session Killer:** Forces Python to drop persistent connections (Keep-Alive), ensuring a fresh circuit for every request.
* **Auto-Port Discovery:** Automatically detects Tor ports on Windows (Tor Browser) and Linux/Kali (Tor Service).
* **Rich UI:** Professional command-line interface with visual progress bars and tables.
* **DNS Leak Protection:** Uses `socks5h://` protocol to resolve DNS queries securely over the Tor network.

## 📸 Screenshots

<img width="1442" height="492" alt="aether" src="https://github.com/user-attachments/assets/6f1691f2-27f1-4f2b-be51-314cfc548bd3" />


## 🛠️ Installation & Usage

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/Kadirveysel/AETHER-Tor-Automation.git
    ```

2.  **Enter the directory:**
    ```bash
    cd AETHER-Tor-Automation
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Run the tool:**
    ```bash
    python main.py
    ```

## ⚠️ Disclaimer

This tool is created for **educational purposes** and authorized security research only. The author is not responsible for any misuse or damage caused by this program. Always obtain permission before testing network defenses.

Authored by **Plansmight**
