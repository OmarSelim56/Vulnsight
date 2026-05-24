# VulnSight

**AI-powered Network Intrusion Detection System**

VulnSight is a real-time NIDS that combines a hybrid CNN-BiLSTM deep learning model with a rule-based signature engine to detect network attacks from live traffic or uploaded PCAP files. It ships with a full-featured React dashboard for alert management, analytics, and reporting.

---

## Features

- **Real-time detection** — captures live traffic via NFStream, classifies flows every cycle, and streams alerts to the dashboard over WebSocket
- **CNN-BiLSTM model** — trained on CIC-IDS-2017 (34 engineered features per flow); decision threshold 0.76
- **Signature engine** — rule-based layer for rate-based attacks (DDoS, port scan, brute force, C2 beacons) that complements the ML model
- **PCAP upload** — upload a `.pcap` file and replay it through the full detection pipeline
- **Attack classification** — automatically labels alerts as `ddos`, `port_scan`, `brute_force`, `data_exfiltration`, `c2_beacon`, or `intrusion`
- **SHAP explainability** — top contributing features shown per alert
- **PDF & CSV export** — generate paginated reports with charts and download alert history as CSV
- **User management** — JWT authentication, role-based access (admin / analyst), user CRUD from the admin panel
- **Data retention** — preview and run cleanup by age, or delete all alerts at once
- **Simulation script** — replay processed dataset CSVs through the live API for testing and demos

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.11+, FastAPI, Uvicorn, SQLite |
| ML | PyTorch (CNN-BiLSTM), scikit-learn (scaler), SHAP |
| Network capture | NFStream |
| Frontend | React 19, TypeScript, Tailwind CSS v4, Recharts |
| Data fetching | TanStack React Query |
| PDF export | html-to-image + jsPDF |
| Auth | Custom HS256 JWT (no external lib) |

---

## Project Structure

```
VulnSight/
├── main.py                   # Single entry point (API + frontend)
├── requirements.txt          # Python dependencies (pinned)
│
├── src/
│   ├── api/
│   │   ├── server.py         # FastAPI app, all routes
│   │   ├── schemas.py        # Pydantic request/response models
│   │   ├── run_api.py        # Uvicorn launcher + SPA static serving
│   │   └── auth/             # JWT auth: routes, dependencies, security
│   ├── core/
│   │   ├── model_arch.py     # CNN-BiLSTM model definition
│   │   ├── feature_config.py # 34 feature names
│   │   └── settings.py       # Env-based configuration
│   ├── db/
│   │   ├── repository.py     # Alert CRUD + analytics queries
│   │   ├── auth_repository.py# User/role CRUD
│   │   └── schema.py         # SQLite schema bootstrap
│   └── detection/
│       ├── manager.py        # Detection lifecycle (start/stop/status)
│       ├── engine.py         # ML inference + SHAP
│       ├── collector.py      # NFStream flow extraction
│       ├── classifier.py     # Attack type labelling
│       └── signatures.py     # Rule-based signature engine
│
├── model/
│   ├── vulnsight_cnn_bilstm.pth  # Trained model weights
│   ├── scaler.pkl                # Feature scaler
│   ├── threshold.json            # Decision threshold (0.76)
│   └── train.py                  # Training script
│
├── dataset/
│   └── preprocess.py         # CIC-IDS-2017 preprocessing script
│
├── frontend/                 # React + Vite application
│   └── src/
│       ├── pages/            # Dashboard, Alerts, Reports, Model, Admin, Live Traffic, Login
│       ├── components/       # AlertTable, DetectionPanel, ShapDrawer, StatCard, …
│       ├── api/client.ts     # Typed API client
│       ├── hooks/            # useWebSocket, useAuth, …
│       └── types/index.ts    # Shared TypeScript types
│
├── testing/
│   └── simulate.py           # Dataset replay simulation script
│
└── tests/                    # pytest test suite
```

---

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 20+ and npm
- A network interface accessible to NFStream (for live capture)

### 1. Clone and install

```bash
git clone https://github.com/OmarSelim56/Vulnsight.git
cd Vulnsight
pip install -r requirements.txt
```

### 2. Install frontend dependencies

```bash
cd frontend
npm install
cd ..
```

### 3. Run VulnSight

```bash
python main.py
```

This starts both services:

| Service | URL |
|---|---|
| API + Swagger docs | http://localhost:8000/docs |
| React dashboard (Vite dev) | http://localhost:5173 |

> **API only** (no frontend): `python main.py --api-only`

### 4. Log in

Default credentials (change in production):

| Field | Value |
|---|---|
| Username | `admin` |
| Password | `admin12345` |

---

## Configuration

All settings are read from environment variables. Override any of them before running:

| Variable | Default | Description |
|---|---|---|
| `VULNSIGHT_API_HOST` | `0.0.0.0` | API bind address |
| `VULNSIGHT_API_PORT` | `8000` | API port |
| `VULNSIGHT_DB_PATH` | `database/vulnsight.db` | SQLite database path |
| `VULNSIGHT_AUTH_JWT_SECRET` | `change-me-in-production` | JWT signing secret |
| `VULNSIGHT_AUTH_TOKEN_EXP_MINUTES` | `60` | Token lifetime in minutes |
| `VULNSIGHT_BOOTSTRAP_ADMIN_USERNAME` | `admin` | Auto-created admin username |
| `VULNSIGHT_BOOTSTRAP_ADMIN_PASSWORD` | `admin12345` | Auto-created admin password |

---

## Dataset & Training

VulnSight was trained on the [CIC-IDS-2017](https://www.unb.ca/cic/datasets/ids-2017.html) dataset.

### Preprocessing

```bash
python dataset/preprocess.py
```

Reads raw CICFlowMeter CSVs from `dataset/raw/`, cleans and normalises them, and writes the processed files to `dataset/processed/`.

### Training

```bash
python model/train.py
```

Trains the CNN-BiLSTM model. Outputs:
- `model/vulnsight_cnn_bilstm.pth` — model weights
- `model/scaler.pkl` — fitted feature scaler
- `model/threshold.json` — optimal decision threshold

---

## Simulation

Replay processed dataset CSVs through the live API to populate the dashboard with realistic data:

```bash
# All CSVs in dataset/processed/
python testing/simulate.py

# Single file
python testing/simulate.py --file Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv

# Scripted multi-phase org scenario
python testing/simulate.py --scenario org

# Options
python testing/simulate.py --rows 200 --delay 0.2 --malicious-only
```

---

## API Reference

Interactive docs available at **http://localhost:8000/docs** when the server is running.

Key endpoint groups:

| Prefix | Description |
|---|---|
| `POST /api/v1/auth/login` | Obtain JWT token |
| `GET /api/v1/alerts` | List alerts |
| `GET /api/v1/detection/status` | Detection engine state |
| `POST /api/v1/detection/start` | Start live capture |
| `POST /api/v1/detection/stop` | Stop live capture |
| `POST /api/v1/upload/pcap` | Upload a PCAP file |
| `GET /api/v1/analytics/*` | Timeline, top attackers, attack types, severity |
| `GET /api/v1/reports/generate` | Generate a report snapshot |
| `GET /api/v1/reports/history` | Saved report list |
| `GET /api/v1/admin/users` | User management (admin only) |
| `POST /api/v1/admin/cleanup` | Delete alerts older than N days |
| `POST /api/v1/admin/cleanup/all` | Delete all alerts |

---

## Running Tests

```bash
pytest tests/
```

---

## License

See [LICENSE](LICENSE).
