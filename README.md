# ARPShield — Real-Time ARP Spoofing Detection and Prevention System

## Project Overview

ARPShield is an advanced network security system designed to detect, analyze, and prevent Address Resolution Protocol (ARP) spoofing attacks in real-time. The primary current system provides a robust defense by combining:
- Real-time ARP monitoring
- Scapy packet capture and parsing
- Trusted IP-MAC baseline checking
- Rule-based ARP spoofing detection (including gateway spoof detection, MAC/IP conflict detection, suspicious ARP detection, and ARP-rate monitoring)
- Attacker identification
- Alerting and logging
- DDoS/DoS impact analysis
- Mitigation and prevention
- A centralized dashboard, backend API, and database for network administrators

This is a **defensive cybersecurity project** built for authorised network environments only.

## Problem Statement

ARP spoofing (or ARP poisoning) is a critical vulnerability in local area networks that allows attackers to intercept, modify, or stop network traffic. Traditional signature-based detection methods often fail to identify sophisticated, low-rate, or novel spoofing patterns. There is a need for a robust system that can actively establish trusted baselines and detect anomalous activities associated with ARP poisoning with high accuracy and low false positives.

## Objectives

- Real-time monitoring of network traffic for ARP packets.
- Accurate detection of ARP spoofing and related anomalous network behaviours using a rule-based heuristic engine and baseline checking.
- Automated mitigation and prevention strategies to isolate threats and restore network integrity.
- Provide a comprehensive, user-friendly dashboard for network administrators to visualise network state and security events.

## System Architecture

The system architecture is highly modular, consisting of:

1. **Network Packet Monitor** (`network/`): Captures and processes raw ARP network traffic using Scapy.
2. **Detection Engine** (`detection/`): Analyses parsed packets to identify standard and complex spoofing attacks using rule-based heuristics and rate monitoring.
3. **Prevention/Mitigation Module** (`prevention/`): Automatically blocks malicious MAC/IP pairs and alerts the administrator.
4. **Backend & Database** (`backend/`, `database/`): Stores network logs, identified threats, and system configuration using Flask and SQLite. Serves API for the dashboard.
5. **Security Dashboard** (`dashboard/`): A web-based interface for visualising system health, alerts, and historical data using Jinja/HTML/CSS.
6. **ML Anomaly Detection Module** (`ml/`) *(Experimental / Future Work)*: Employs trained Isolation Forest models to classify network behaviour based on engineered ARP traffic features.

## Module Development Status

| Module | Directory | Status | Owner |
|--------|-----------|--------|-------|
| Network Monitoring | `network/` | ✅ Implemented | Person 1 |
| Detection Engine | `detection/` | ✅ Implemented | Person 2 |
| **Testing & Evaluation** | **`testing/`** | **✅ Implemented** | **Person 3** |
| Prevention & Response | `prevention/` | ✅ Implemented | Person 4 |
| Backend, DB & Dashboard | `backend/`, `database/`, `dashboard/` | ✅ Implemented | Person 5 |
| **ML Anomaly Detection** | **`ml/`** | **✅ Pipeline implemented (Experimental)** | **Person 3** |

> **Note:** The testing & evaluation module (Person 3) provides controlled scenario testing, cybersecurity detection metrics, and DDoS impact analysis for the rule-based detection engine. See [`testing/README.md`](testing/README.md) for detailed documentation.

## AI/ML Component (Experimental / Future Work)

An Isolation Forest-based machine learning pipeline is included in the repository as an experimental extension. It is currently isolated from the live detection and prevention pipeline and is not used to generate the final real-time detection or performance results.

The experimental AI/ML module (`ml/`) uses an **Isolation Forest** model for unsupervised anomaly detection on ARP network traffic features. It processes time-windowed ARP observations into 10 engineered features that capture request/reply patterns, MAC-IP mapping instability, and traffic concentration — all indicators relevant to detecting anomalous ARP behaviour.

See [`ml/README.md`](ml/README.md) for detailed documentation of the ML pipeline.

## Technology Stack

**Primary System:**
- **Programming Language**: Python 3
- **Network Processing**: Scapy
- **Backend Framework**: Flask
- **Frontend / Dashboard**: Jinja, HTML, CSS, JavaScript
- **Database**: SQLite
- **Testing**: pytest, unittest

**Experimental ML Extension:**
- **Machine Learning**: scikit-learn (Isolation Forest), pandas, NumPy, joblib, matplotlib

## Five-Person Module Division

1. **Lead / Core Architecture & Network Module**: Responsible for packet capturing, basic network scripts, and integration.
2. **Detection Engine & Rule-Based Heuristics**: Builds the logic for static and dynamic analysis and validation of network anomalies.
3. **Testing, Evaluation & Experimental ML**: Focuses on controlled scenario testing, DDoS impact analysis, and the experimental Isolation Forest pipeline.
4. **Prevention Mechanism & Security Actions**: Develops the automated response system, firewall rule integration, and alert generation.
5. **Backend, Database & Dashboard**: Handles API development, database management, and building the user interface for administrators.

## Future Scope

- Integration of the experimental AI/ML Isolation Forest pipeline into the live production environment.
- Integration with SDN (Software-Defined Networking) controllers.
- Support for detecting other Layer 2 attacks (e.g., MAC flooding, DHCP spoofing).
- Cloud-based threat intelligence sharing.
- Advanced predictive analytics for network health.
