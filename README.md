# ARPShield — AI-Driven ARP Spoofing Detection and Prevention System

## Project Overview

ARPShield is an advanced, intelligent network security system designed to detect, analyze, and prevent Address Resolution Protocol (ARP) spoofing attacks in real-time. By leveraging Artificial Intelligence and Machine Learning techniques, the system provides a hybrid defence combining real-time ARP monitoring, rule-based heuristic detection, ML-based anomaly detection, risk assessment, automated defensive response, and a security dashboard for network administrators.

This is a **defensive cybersecurity project** built for authorised network environments only.

## Problem Statement

ARP spoofing (or ARP poisoning) is a critical vulnerability in local area networks that allows attackers to intercept, modify, or stop network traffic. Traditional signature-based detection methods often fail to identify sophisticated, low-rate, or novel spoofing patterns. There is a need for an intelligent system that can dynamically learn network behaviour and identify anomalous activities associated with ARP poisoning with high accuracy and low false positives.

## Objectives

- Real-time monitoring of network traffic for ARP packets.
- Accurate detection of ARP spoofing and related anomalous network behaviours using AI/ML.
- Automated mitigation and prevention strategies to isolate threats and restore network integrity.
- Provide a comprehensive, user-friendly dashboard for network administrators to visualise network state and security events.

## System Architecture

The system architecture is highly modular, consisting of:

1. **Network Packet Monitor** (`network/`): Captures and processes raw ARP network traffic using Scapy.
2. **Detection Engine** (`detection/`): Analyses parsed packets to identify standard and complex spoofing attacks using rule-based heuristics.
3. **ML Anomaly Detection Module** (`ml/`): Employs trained Isolation Forest models to classify network behaviour as normal or anomalous based on engineered ARP traffic features.
4. **Prevention/Mitigation Module** (`prevention/`): Automatically blocks malicious MAC/IP pairs and alerts the administrator.
5. **Backend & Database** (`backend/`, `database/`): Stores network logs, identified threats, and system configuration. Serves API for the dashboard.
6. **Security Dashboard** (`dashboard/`): A web-based interface for visualising system health, alerts, and historical data.

## Module Development Status

| Module | Directory | Status | Owner |
|--------|-----------|--------|-------|
| Network Monitoring | `network/` | ✅ Implemented | Person 1 |
| Detection Engine | `detection/` | 🔲 Under development | Person 2 |
| **ML Anomaly Detection** | **`ml/`** | **✅ Pipeline implemented** | **Person 3** |
| Prevention & Response | `prevention/` | 🔲 Under development | Person 4 |
| Backend, DB & Dashboard | `backend/`, `database/`, `dashboard/` | 🔲 Under development | Person 5 |

> **Note:** Not all modules are complete. The network monitoring module captures ARP traffic and provides labelled data. The ML pipeline has been trained on Person 1's captured data (6,000 records) achieving 88.73% accuracy on anomaly detection.

## AI/ML Component

The AI/ML module (`ml/`) uses an **Isolation Forest** model for unsupervised anomaly detection on ARP network traffic features. It processes time-windowed ARP observations into 10 engineered features that capture request/reply patterns, MAC-IP mapping instability, and traffic concentration — all indicators relevant to detecting anomalous ARP behaviour.

See [`ml/README.md`](ml/README.md) for detailed documentation of the ML pipeline.

## Technology Stack

- **Programming Language**: Python
- **Machine Learning**: scikit-learn (Isolation Forest), pandas, NumPy, joblib, matplotlib
- **Network Processing**: Scapy
- **Backend Framework**: Flask / FastAPI
- **Frontend / Dashboard**: React or Vue.js, HTML/CSS/JavaScript
- **Database**: PostgreSQL / SQLite (for development)

## Five-Person Module Division

1. **Lead / Core Architecture & Network Module**: Responsible for packet capturing, basic network scripts, and integration.
2. **AI/ML Development**: Focuses on feature engineering, model training (Isolation Forest), and integration of the ML anomaly detection engine.
3. **Detection Engine & Rule-Based Heuristics**: Builds the logic for static and dynamic analysis and validation of network anomalies.
4. **Prevention Mechanism & Security Actions**: Develops the automated response system, firewall rule integration, and alert generation.
5. **Backend, Database & Dashboard**: Handles API development, database management, and building the user interface for administrators.

## Future Scope

- Integration with SDN (Software-Defined Networking) controllers.
- Support for detecting other Layer 2 attacks (e.g., MAC flooding, DHCP spoofing).
- Cloud-based threat intelligence sharing.
- Advanced predictive analytics for network health.
- Ensemble models and deep-learning-based anomaly detection.
