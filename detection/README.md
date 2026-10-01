# ARP Spoofing Detection Engine

> **Person 2 Module** — Rule-based ARP spoofing detection for the
> *ARP Spoofing Attack Detection to Prevent DDoS Attack* project.

This module ingests parsed ARP packets (from Person 1's monitoring
layer), applies a set of explainable detection rules, and emits
structured alerts for downstream mitigation (Person 4), backend
storage (Person 5), and evaluation (Person 3).

No machine learning. Every alert is traceable to a specific rule,
reason, and packet.

---

## Table of Contents

- [Features](#features)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Configuration](#configuration)
- [Quick Start](#quick-start)
- [Packet Input Contract](#packet-input-contract)
- [Alert Output Contract](#alert-output-contract)
- [Detection Rules](#detection-rules)
- [Severity Levels](#severity-levels)
- [Testing](#testing)
- [Integration Points](#integration-points)
- [Design Notes](#design-notes)
- [Scope and Safety](#scope-and-safety)

---

## Features

- Real-time, stateful ARP spoofing detection
- Trusted IP–MAC baseline verification
- Gateway impersonation detection
- IP–MAC conflict and duplicate claim detection
- Unexpected MAC change detection
- Suspicious / gratuitous ARP reply detection
- ARP request/reply rate threshold detection (DoS/flood)
- Severity classification: **Low / Medium / High / Critical**
- Alert deduplication with cooldown window
- Clean JSON alert output for backend integration
- Fully rule-based and explainable (no ML)

---

## Project Structure

