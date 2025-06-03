# 🛰️ RAJ-IS0: Network Vulnerability Discovery Project

## 📡 Overview

**RAJ-IS0** is a Bash script designed to assist in basic **network vulnerability discovery** by automating common network scanning tasks using **nmap** and **netdiscover**. It allows users to:

- Scan a target IP address
- Discover live hosts on the network
- Identify operating systems and vendors
- Perform detailed port, version, and vulnerability scans on selected hosts

> ⚠️ **Important:** This tool is intended strictly for educational purposes and ethical hacking **only** on networks where you have **explicit permission**. Unauthorized use is illegal and unethical.

---

## ✨ Features

- ✅ **Interactive Target Input** – Prompts for an IP address
- ✅ **CIDR Deduction** – Automatically determines the /24 subnet
- ✅ **Live Host Discovery** – Optional use of `netdiscover` to locate active hosts
- ✅ **Network-wide OS Detection** – Uses `nmap` to find MAC addresses and OS info
- ✅ **Selective Host Scanning** – Choose specific or all hosts for detailed scanning
- ✅ **Comprehensive Nmap Scans**:
  - Full port scan (`-p-`)
  - Service version detection (`-sV`)
  - OS detection (`-O`)
  - Vulnerability script scanning (`-sC`)

---

## 🧰 Prerequisites

Ensure the following tools are installed (default in **Kali Linux**):

- [`nmap`](https://nmap.org): Network discovery and security auditing
- [`netdiscover`](https://github.com/alexxy/netdiscover): ARP reconnaissance tool
- `bash`: Standard shell interpreter

Install if needed:

```bash
sudo apt update
sudo apt install nmap netdiscover
