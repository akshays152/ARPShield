# ARPShield 🛡️
**Real-Time ARP Spoofing Detection and DDoS Prevention System**

> **B.Tech Capstone Project (Group 52)**
> **VIT Bhopal University**
> **Program:** B.Tech – Computer Science and Engineering (Cyber Security and Digital Forensics)
> **Supervisor:** Dr. Sreevani Maddukuri

---

## 📌 Project Overview
ARPShield is a comprehensive, defensive cybersecurity system designed to detect, analyze, mitigate, and recover from Address Resolution Protocol (ARP) spoofing attacks in real-time. Built specifically for authorized network environments, ARPShield provides a robust, **rule-based** network defense architecture. It actively captures network traffic, establishes a trusted baseline for IP-MAC mappings, and applies heuristic detection rules to accurately identify spoofing, rate anomalies, and potential Denial of Service (DoS) behaviors. 

## 🎯 Problem Statement
ARP spoofing (or ARP poisoning) is a critical Layer 2 vulnerability in local area networks. By forging ARP replies, attackers can associate their MAC address with the IP address of another host (such as the default gateway), leading to traffic interception, Man-in-the-Middle (MitM) attacks, or Network Denial of Service (DDoS/DoS). Traditional signature-based tools often lack real-time visibility, automated mitigation, and clear impact analysis. ARPShield addresses this by providing an intelligent, active, and fully integrated defense pipeline.

## 🚀 Objectives
1. **Real-time Monitoring:** Passively capture and parse ARP packets on the local network.
2. **Robust Rule-Based Detection:** Identify specific attack patterns (gateway spoofing, conflicts, high rates) using strict IP-MAC baseline configurations.
3. **Automated Mitigation & Recovery:** Instantly isolate malicious actors via system-level firewall rules and orchestrate network recovery.
4. **Impact Analysis:** Quantify the actual disruption of the attack (DDoS impact, latency, packet rates).
5. **Centralized Visibility:** Provide a comprehensive security dashboard, RESTful API backend, and persistent database for administrators.

---

## 🏗️ System Architecture & Features

The live ARPShield pipeline operates entirely on a robust, **rule-based detection** model. It consists of the following integrated modules:

### 1. Network Packet Monitor (`network/`)
- Uses **Scapy** to passively sniff the network for ARP packets (Requests and Replies).
- Extracts critical headers (Sender IP, Sender MAC, Target IP, Target MAC, Timestamp).

### 2. Detection Engine (`detection/`)
The core of ARPShield, operating on predefined heuristics and a trusted baseline configuration:
- **IP-MAC Mapping & Baseline Validation:** Cross-references incoming packets against `config/trusted_baseline.json`.
- **Gateway Spoofing Detection:** Flags any non-gateway MAC attempting to claim the network gateway's IP.
- **MAC/IP Conflict Detection:** Identifies when an established IP suddenly appears with a different MAC.
- **Duplicate IP Detection:** Alerts when multiple distinct MAC addresses claim the same IP.
- **Suspicious ARP Detection:** Catches unsolicited (gratuitous) ARP replies lacking a preceding request.
- **ARP-Rate Monitoring:** Tracks packets-per-second (PPS) per MAC address to identify ARP floods and DDoS precursors.
- **Attacker Identification:** Pinpoints the source MAC and IP responsible for the anomalies.

### 3. Prevention, Mitigation & Recovery (`prevention/`)
- **Isolation Actions:** Automatically generates OS-level firewall rules (e.g., `iptables`, Windows Firewall) to block the attacking MAC/IP.
- **Network Recovery:** Capable of broadcasting corrective Gratuitous ARP packets to restore legitimate IP-MAC mappings across the network post-mitigation.

### 4. Testing, Evaluation & DDoS Impact Analysis (`testing/`)
- Contains a synthetic packet generator and testing suite.
- Calculates standard cybersecurity metrics (Accuracy, Precision, Recall, F1 Score).
- Measures **DDoS/DoS Impact** by comparing normal vs. abnormal traffic rates (PPS), evaluating network disruption factors, and calculating average detection latency.

### 5. Backend, Database & Dashboard (`backend/`, `database/`, `dashboard/`)
- **Backend API:** Built with **Flask**, serving RESTful endpoints for all modules.
- **Database:** Uses **SQLite** via SQLAlchemy to persist alerts, devices, incidents, mitigation logs, and impact analyses.
- **Security Dashboard:** Built with **Jinja, HTML, and CSS**, providing a web-based GUI for administrators to visualize active threats, review logs, and monitor network health.

---

## 🧪 Experimental ML Extension (Future Work)

**Status: Experimental (Isolated from the live pipeline)**

An **Isolation Forest-based machine learning pipeline** is included in the repository (`ml/`) as an experimental extension. It processes time-windowed ARP observations into engineered features that capture request/reply patterns, MAC-IP instability, and traffic concentration. 

> **Important:** The ML pipeline is strictly documented as future work. It is *not* currently imported, executed, or used by the live detection engine, mitigation modules, or final performance evaluation metrics.

See [`ml/README.md`](ml/README.md) for detailed documentation.

---

## 💻 Technology Stack

**Primary Production System:**
- **Programming Language:** Python 3
- **Network Capture & Analysis:** Scapy
- **Backend Framework:** Flask
- **Database:** SQLite (via Flask-SQLAlchemy)
- **Frontend Dashboard:** Jinja Templates, HTML5, CSS3, JavaScript
- **Testing & Evaluation:** `unittest`, `pytest`

**Experimental ML Extension:**
- **Machine Learning:** scikit-learn (Isolation Forest), pandas, NumPy, joblib, matplotlib

---

## 👥 Team Members & Responsibilities

| Name | Reg. No | Core Responsibility |
| :--- | :--- | :--- |
| **Chintanika M** | 23BCY10056 | Core Architecture & Network Monitoring (`network/`) |
| **Rishima Sharma** | 23BCY10076 | Detection Engine & Rule-Based Heuristics (`detection/`) |
| **Anju Kumari** | 23BCY10022 | Testing, Evaluation & Experimental ML (`testing/`, `ml/`) |
| **Akshay Singh** | 23BCY10141 | Prevention, Mitigation & Recovery Actions (`prevention/`) |
| **Oveiya K** | 23BCY10129 | Backend API, Database, and Security Dashboard (`backend/`, `dashboard/`) |

---

## ⚙️ Installation & Usage

### 1. Prerequisites
- Python 3.8+
- Npcap (Windows) or libpcap (Linux) for Scapy to function correctly.
- Administrative / Root privileges (required for packet sniffing and firewall modifications).

### 2. Setup
Clone the repository and install the dependencies:
```bash
git clone https://github.com/akshays152/ARPShield.git
cd ARPShield
pip install -r requirements.txt
```

### 3. Running the Live System (Backend + Dashboard)
Start the Flask backend server. This will initialize the SQLite database and start the web dashboard.
```bash
python -m backend.app
```
*Access the dashboard via browser at: `http://127.0.0.1:5000`*

### 4. Running the Testing & Evaluation Framework
To run the automated scenario tests, validate the rule-based detection engine, and generate the final evaluation reports (including DDoS impact analysis and charts):
```bash
python run_final.py
```
*Results will be saved in the `final_evaluation/` directory.*

To run the standard unit test suite:
```bash
python -m unittest discover tests/
```

---

## 📈 Evaluation Results

Based on the latest integration testing of the Rule-Based Detection Engine:

- **Accuracy:** 83.33%
- **Detection Rate (Recall):** 100.00% *(Successfully detected Gateway Spoofing, IP-MAC Conflicts, Duplicate IPs, Suspicious Replies, and High ARP Rates)*
- **F1 Score:** 90.91%
- **Average Detection Latency:** ~1.96 ms
- **DDoS Validation:** Successfully identified abnormal traffic spikes (e.g., from 0.5 PPS up to 9.2+ PPS) during active ARP spoofing attacks.

*(Note: The 100% False Positive Rate in specific edge cases is a direct, intended result of the Detection Engine strictly enforcing the `config/trusted_baseline.json` against synthetic test data that intentionally falls outside the trusted baseline.)*

---
*Developed for authorized academic research and defensive network security. Do not deploy on networks without explicit permission.*
