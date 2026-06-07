<div align="center">
  <img src="docs/images/7ARTH (1).png" alt="7arth Logo" width="120"/>
  <h1>7arth — Network Intrusion Detection System</h1>
  <p><strong>Multi-Module AI-Powered NIDS with Real-Time Dashboard</strong></p>
  <p>
    <a href="https://github.com/Amrtarek113/7arth/blob/main/LICENSE">
      <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"/>
    </a>
    <a href="https://github.com/Amrtarek113/7arth">
      <img src="https://img.shields.io/github/repo-size/Amrtarek113/7arth" alt="GitHub repo size"/>
    </a>
    <a href="https://www.python.org/downloads/">
      <img src="https://img.shields.io/badge/python-3.10%2B-blue" alt="Python 3.10+"/>
    </a>
  
  
  </p>
</div>

---

## 📋 Overview

**7arth** is a comprehensive, multi-module Network Intrusion Detection System (NIDS) developed as a graduation project. It combines traditional machine learning models, deep learning (GRU/LSTM), autoencoders for IoT, ransomware detection, URL phishing detection, APT attack detection, and a real-time interactive dashboard — all in one unified platform.

> **Supervised by:** Dr. Walid Gabril, Dr. Shaimaa El-Sabbagh, Eng. Amira Basyouni, Eng. Shorouk Abdel-Nasser  
> **Team:** Amr Tarek, Mahmoud Magdi, Ahmed Mostafa, Fatma Mohamed, Merna Elsayed, Israa Ibrahim, Doaa Ibrahim, Diaa Mohamed, Hager Ibrahim, Ahmed Mohamed Abdelaziz

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| **Attack Detection** | Binary (normal/attack) + Multi-class (9 attack categories + normal) classification |
| **Real-Time Dashboard** | Flask-based web dashboard with live packet monitoring, charts, and alerts |
| **IoT Anomaly Detection** | Quantized Autoencoder (QAE) model for IoT device traffic analysis |
| **Ransomware Detection** | Memory-based malware detection using K-Nearest Neighbors |
| **URL Phishing Detection** | Random Forest & XGBoost for malicious URL classification |
| **APT Attack Detection** | PyTorch-based Advanced Persistent Threat detection |
| **Auto Detection Engine** | Autonomous thread replays offline data every 5 seconds simulating real-time detection |
| **Network Forensics** | PCAP file upload & analysis with 39 flow feature extraction |
| **Geolocation Mapping** | GeoIP integration for source IP location visualization |

---

## 🏗️ Architecture

```
7arth/
├── attack_detect/          # Core NIDS: binary + multi-class classification
│   ├── code/               # Jupyter notebooks, feature extraction
│   ├── data/               # UNSW-NB15 training/testing datasets
│   └── model/              # RF, DT, GB, MLP, ExtraTrees trained models
├── IOT/                    # IoT anomaly detection (Autoencoder + Quantum)
│   ├── Auto_encoder_detection/
│   └── Quantam_anomly_detection/
├── ransomware_detect/      # Memory-based ransomware detection
├── url/                    # URL phishing detection
│   ├── model/              # xgb.pkl, xgboost_final.pkl
│   ├── data/               # malicious_phish.csv
│   └── test and train/     # Train/test splits
├── APT_Detect/             # Advanced Persistent Threat detection (PyTorch)
├── Real-time-IDS-master/   # PCAP flow extraction pipeline (39 features)
├── Dashboard Site/         # Production Flask + React dashboard
│   ├── backend/            # Flask API, trained models, autonomous detection
│   ├── frontend/           # React (MUI) + Charts (Chart.js)
│   └── uploads/            # PCAP file upload directory
└── docs/                   # Documentation, images, presentation
```

---

## 🗃️ Datasets

| Dataset | Records | Classes | Usage |
|---------|---------|---------|-------|
| [UNSW-NB15](https://research.unsw.edu.au/projects/unsw-nb15-dataset) | 175,341 training / 82,332 testing | 2 (binary) / 10 (multi-class) | Attack detection, Dashboard |
| [CIC IoT 2023](https://www.unb.ca/cic/datasets/iotdataset-2023.html) | ~50,000 | 2 (benign/malicious) | IoT anomaly detection |
| [RT-IoT2022](https://www.kaggle.com/datasets/agungpambudi/rt-iot2022) | ~52,000 | 2 | IoT autoencoder |
| [Obfuscated-MalMem2022](https://www.kaggle.com/datasets/discordnaveen/obfuscated-malmem2022) | 58,596 | 2 (malicious/benign) | Ransomware detection |
| [Malicious URLs](https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset) | 651,191 | 3 (benign/phishing/malware/deface) | URL phishing detection |


---

## 🚀 Quick Start

### Prerequisites

- Python 3.10+
- Node.js 18+
- pip / conda
- Wireshark / TShark (optional, for live packet capture)

### 1. Clone

```bash
git clone https://github.com/Amrtarek113/7arth.git
cd 7arth
```

### 2. Dashboard Backend

```bash
cd "Dashboard Site/backend"
python -m venv venv
# Windows: .\venv\Scripts\activate
# Linux/macOS: source venv/bin/activate
pip install -r requirements.txt
python app.py
```

> Dashboard runs at **http://localhost:8080**  
> Login: `7arth@gmail.com` / `7arth123456789`

### 3. Frontend (development)

```bash
cd "Dashboard Site/frontend"
npm install
npm start
```

> React dev server on **http://localhost:3000**

### 4. Jupyter Notebooks

```bash
cd 7arth/attack_detect/code
jupyter notebook unsw_nb15_student.ipynb
```

### 5. PCAP Flow Extraction

```bash
cd Real-time-IDS-master/flow
python Flow.py path/to/traffic.pcap
```

---

## 🧪 Running Tests

```bash
# Backend tests
cd "Dashboard Site/backend"
python -m pytest tests/

# Lint
cd "Dashboard Site/backend"
flake8 app.py
```

---

## 🔧 GitHub Actions

| Workflow | Trigger | Description |
|----------|---------|-------------|
| `deploy-pages.yml` | Push to `main` | Builds frontend & deploys to GitHub Pages |
| `lint-test.yml` | Push & PR | Runs Python linting + backend tests |
| `build-frontend.yml` | Push to `main` | Builds React frontend static files |

---

## 📁 Docs & Presentation

- 📄 [7arth Book (Word)](7arth%20book.docx) — Full project documentation
- 📽️ [Project Presentation (PowerPoint)](project%20presentation%20.pptx) — Defense slides
- 📊 [Notebook Figures](7arth/attack_detect/code/iframe_figures/) — Interactive visualizations

---

## 📬 Contact

Created by the **7arth Team** — Faculty of ... | Supervised by Dr. Walid Gabril, Dr. Shaimaa El-Sabbagh, Eng. Amira Basyouni, Eng. Shorouk Abdel-Nasser.

---

<div align="center">
  <sub>Built with ❤️ for graduation | 7arth — Network Intrusion Detection System</sub>
</div>
