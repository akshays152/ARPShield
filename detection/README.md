# ARPShield - Rule-Based ARP Spoofing Detection Module

## Overview
A comprehensive rule-based detection module for identifying ARP spoofing attacks in network environments. Provides real-time detection with structured output.

## Features
- 🛡️ **5 Detection Rules**: IP-MAC changes, Duplicate IP claims, Gateway monitoring, Unusual activity, ARP storms
- 📊 **Structured Output**: Standardized detection results with severity levels
- 🔄 **Real-Time Processing**: Process ARP packets as they arrive
- 💾 **JSON Export**: Easy integration with other tools
- 🧪 **Mock Data Support**: Built-in testing capabilities

## Installation

```bash
# Clone repository
git clone https://github.com/yourusername/ARPShield-Detection.git
cd ARPShield-Detection

# Install dependencies
pip install -r requirements.txt

# Install package
pip install -e .