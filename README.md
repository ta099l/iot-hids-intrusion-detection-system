# 🔐 IoT Host-Based Intrusion Detection System (IoT-HIDS)

A lightweight **host-based Intrusion Detection System (IDS)** designed for monitoring network traffic in **IoT and Industrial Control Systems (ICS)** environments.

The system captures packets in real time, analyzes them using multiple detection layers, and generates structured alerts for suspicious or malicious activity.

---

## 🚀 Features

* 📡 Real-time packet capture using Scapy
* 🧠 Multi-layer threat detection system
* 🌐 IP reputation analysis (local IOC + AbuseIPDB)
* ⚙️ ICS-specific security rules (port whitelisting & spoofing detection)
* 📊 Risk scoring engine for alert prioritization
* 🗂️ Structured alert logging (JSON format)
* ⚡ Caching & rate-limiting for performance optimization
* 🖥️ Web-based dashboard (FastAPI) for monitoring alerts

---

## 🛠️ Tech Stack

* **Language:** Python
* **Networking:** Scapy
* **Backend:** FastAPI
* **Frontend:** HTML, CSS, JavaScript
* **Data Handling:** JSON
* **External APIs:** AbuseIPDB

---

## ⚙️ How It Works

1. 📥 Capture live network packets from the device
2. 🔍 Extract packet features (IP, ports, protocol, connection state)
3. 🧠 Analyze traffic using:

   * IP reputation (IOC feeds + AbuseIPDB)
   * Port-based rules (ICS policies, high-risk ports)
   * Spoofing detection
4. 📊 Assign a risk score based on detected anomalies
5. 🚨 Generate alerts when thresholds are exceeded
6. 📁 Log alerts and display them in a dashboard

---

## ▶️ Installation & Setup

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/iot-hids.git
cd iot-hids
```

### 2. Install dependencies

```bash
pip install scapy requests python-dotenv fastapi uvicorn
```

### 3. Configure environment variables

Create a `.env` file:

```env
ABUSEIPDB_KEY=your_api_key_here
```

### 4. Run the IDS

```bash
sudo python3 main.py
```

---

## 🖥️ Run the Dashboard

```bash
uvicorn app:app --reload
```

Then open:

```
http://127.0.0.1:8000
```

---

## 📊 Example Detection

```
================================ IDS ALERT =================================
Score reached: 120
Flow: 10.0.0.8:502 → 192.168.1.5:502
State: NEW | Direction: INBOUND

Reasons:
• Unauthorized access on ICS port
• Suspicious IP detected
===========================================================================
```

---

## 🔐 Security Capabilities

* Detection of unauthorized ICS access
* Malicious IP communication
* Source spoofing attempts
* Suspicious outbound connections (C2 behavior)
* High-risk port activity

---

## 📌 Future Improvements

* Machine learning-based anomaly detection
* Real-time alert notifications
* Enhanced dashboard visualizations
* Distributed IDS support

---

## 👥 Contributors

This project was developed as part of a **Network Security course**.

* Focus contribution: **Dashboard development, visualization, and system presentation**

---

## ⭐ Why This Project Matters

This project demonstrates:

* Real-world **network security implementation**
* Understanding of **intrusion detection systems**
* Experience with **low-level networking + backend systems**
* Ability to build **end-to-end security solutions**
