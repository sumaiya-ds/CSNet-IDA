#  CSNet-IDA

## Two-Stage Network Intrusion Detection & Security Intelligence Platform

**CSNet-IDA** is a machine-learning-based Network Intrusion Detection System (IDS) that combines hierarchical Random Forest classification with a web-based Security Operations Center (SOC) interface for network traffic analysis, attack-family classification, incident management, simulation, and model inspection.

> **Detect → Classify → Investigate → Respond**

###  Live Demo

**[Launch CSNet-IDA SOC Platform](https://csnet-ida.onrender.com/)**

**[View Source Code](https://github.com/sumaiya-ds/CSNet-IDA)**

---

##  Overview

Traditional intrusion detection systems can identify suspicious network traffic, but simply producing a classification is not enough for security operations.

CSNet-IDA extends a two-stage machine-learning IDS into an interactive security intelligence platform.

The system takes **40 NSL-KDD connection features** and processes them through a hierarchical inference pipeline:

```text
                    NETWORK CONNECTION
                           │
                           ▼
                  40 RAW NSL-KDD FEATURES
                           │
                           ▼
                FEATURE PREPROCESSING
                  40 → 120 FEATURES
                           │
                           ▼
              ┌────────────────────────┐
              │       STAGE 1          │
              │   RANDOM FOREST IDS    │
              │                        │
              │   Normal vs Attack     │
              │   Threshold τ = 0.40   │
              └───────────┬────────────┘
                          │
                 ┌────────┴────────┐
                 │                 │
              NORMAL            ATTACK
                 │                 │
                 │                 ▼
                 │       ┌────────────────────┐
                 │       │      STAGE 2       │
                 │       │  RANDOM FOREST     │
                 │       │                    │
                 │       │ Attack Family      │
                 │       └─────────┬──────────┘
                 │                 │
                 │       ┌─────────┼─────────┐
                 │       ▼         ▼         ▼
                 │      DoS      Probe      R2L
                 │                           │
                 │                           ▼
                 │                          U2R
                 │
                 ▼
             NORMAL
                          │
                          ▼
                 SOC INTELLIGENCE LAYER
                          │
          ┌───────────────┼────────────────┐
          ▼               ▼                ▼
      Telemetry       Incidents       Investigation
          │               │                │
          └───────────────┼────────────────┘
                          ▼
                   SECURITY POSTURE
```

---

# 🎯 Core Capabilities

### Machine Learning

* Two-stage hierarchical Random Forest architecture
* Binary Normal/Attack detection
* Attack-family classification
* DoS, Probe, R2L and U2R classification
* Configurable Stage 1 probability threshold
* Reusable fitted preprocessing pipeline
* Real-time inference using the saved model artifacts

### Security Operations

* SOC-style command center
* Security posture calculation
* Live traffic telemetry
* Attack-rate monitoring
* Attack-family distribution
* Severity distribution
* Protocol and service statistics
* Active critical incident tracking

### Incident Management

* Automatic incident generation
* Incident identifiers
* Attack family and severity classification
* Stage 1 probability tracking
* 40-feature flow snapshots
* Incident filtering and sorting
* Search
* Incident investigation workstation
* Lifecycle management:

```text
NEW
 ↓
INVESTIGATING
 ↓
CONFIRMED
 ↓
RESOLVED
```

### Network Simulation

The platform includes deterministic NSL-KDD-based scenarios for demonstrating the complete detection pipeline:

| Scenario            | Traffic                         | Expected Classification |
| ------------------- | ------------------------------- | ----------------------- |
| Normal Baseline     | Legitimate enterprise traffic   | Normal                  |
| Port Reconnaissance | IPSweep / scanning              | Probe                   |
| DoS Storm           | Neptune SYN flood               | DoS                     |
| R2L Intrusion       | Warezclient / remote compromise | R2L                     |
| U2R Escalation      | Rootkit / privilege escalation  | U2R                     |
| Mixed Incursion     | Controlled multi-stage sequence | Multiple families       |

Simulation mode is explicitly identified in the application so that demonstration traffic is not presented as live packet capture.

---

#  Two-Stage Machine Learning Architecture

## Stage 1 — Binary Detection

The first Random Forest determines whether an input connection is:

```text
Normal
   or
Attack
```

The deployed inference pipeline uses:

```text
P(Attack) ≥ 0.40  →  Attack
P(Attack) < 0.40  →  Normal
```

The threshold is configurable in the Connection Inspector.

### Internal Evaluation

| Metric        | Result |
| ------------- | -----: |
| Accuracy      | 99.93% |
| Normal Recall | 99.94% |
| Attack Recall | 99.91% |

---

## Stage 2 — Attack Family Classification

Connections identified as attacks by Stage 1 are passed to a second Random Forest.

The classifier identifies:

* **DoS** — Denial of Service
* **Probe** — Surveillance / scanning
* **R2L** — Remote to Local
* **U2R** — User to Root

### Internal Evaluation

| Attack Family | Precision | Recall |   F1 |
| ------------- | --------: | -----: | ---: |
| DoS           |      1.00 |   1.00 | 1.00 |
| Probe         |      1.00 |   1.00 | 1.00 |
| R2L           |      1.00 |   0.99 | 1.00 |
| U2R           |      0.75 |   1.00 | 0.86 |

**Overall Stage 2 Accuracy: 99.98%**

The U2R category contains comparatively few samples, so its metrics should be interpreted with caution.

---

#  NSL-KDD Dataset

CSNet-IDA is based on the **NSL-KDD network intrusion detection benchmark dataset**.

The connection records contain network-level features describing:

* Connection duration
* Protocol type
* Network service
* Connection flag
* Source and destination bytes
* Authentication activity
* Privilege escalation indicators
* Connection statistics
* Host-based traffic statistics

The raw dataset is intentionally excluded from the repository where applicable.

---

#  Feature Processing

The inference interface accepts **40 connection features**.

Categorical attributes include:

```text
protocol_type
service
flag
```

A fitted Scikit-learn preprocessing pipeline transforms the original representation:

```text
40 input features
       ↓
ColumnTransformer
       ↓
120 transformed features
```

The exact fitted preprocessing artifact used during model development is reused during inference to maintain consistency between training and deployment.

---

#  Model Artifacts

The saved model artifacts are stored under `models/`.

| Artifact                                  | Purpose                        |
| ----------------------------------------- | ------------------------------ |
| `random_forest_final.pkl`                 | Stage 1 binary classifier      |
| `preprocessor_final.pkl`                  | Feature preprocessing pipeline |
| `threshold_final.pkl`                     | Stage 1 decision threshold     |
| `attack_family_random_forest_final.pkl`   | Stage 2 classifier             |
| `attack_family_labels_final.pkl`          | Stage 2 label mapping          |
| `intrusion_detection_two_stage_final.pkl` | Combined IDS artifact          |

**The deployed application uses these saved artifacts directly.**

No model retraining is performed during application startup or inference.

---

#  SOC Platform

The ML pipeline is exposed through a FastAPI-powered web application.

## Command Center

Provides an operational overview containing:

* Security posture
* Total analyzed flows
* Detected incursions
* Critical incidents
* Average inference latency
* Traffic telemetry
* Attack-family distribution
* Severity distribution
* Protocol distribution
* Recent incidents

## Live Network Monitor

The monitor provides:

* Deterministic traffic simulation
* Step-by-step replay
* Continuous streaming
* Scenario selection
* Attack filtering
* Stage 1 probability telemetry
* Flow-level inspection
* Incident generation

## Incident Center

Security events can be:

* searched
* filtered
* sorted
* investigated
* escalated
* confirmed
* resolved
* exported

## Connection Inspector

A complete 40-feature connection vector can be submitted manually or populated using verified benchmark presets.

The inspector exposes the complete decision path:

```text
40 Features
     ↓
120 Transformed Features
     ↓
Stage 1 Random Forest
     ↓
Attack Probability
     ↓
Stage 2 Random Forest
     ↓
Attack Family
     ↓
Severity
```

---

#  Verified Demonstration Presets

The platform includes representative NSL-KDD-derived presets for validating the deployed inference pipeline.

| Preset      | Stage 1 | Final Prediction | Severity |
| ----------- | ------- | ---------------- | -------- |
| Normal      | Normal  | Normal           | Low      |
| Neptune     | Attack  | DoS              | Critical |
| IPSweep     | Attack  | Probe            | Medium   |
| Warezclient | Attack  | R2L              | High     |
| Rootkit     | Attack  | U2R              | Critical |

These presets provide deterministic examples for demonstrations and application-level testing.

---

#  Evaluation & Generalization

The project distinguishes between internal model evaluation and external benchmark validation.

### Internal Evaluation

A held-out test distribution was used during model development and evaluation.

### External Evaluation

The system was additionally evaluated against **KDDTest+** to examine generalization beyond the internal evaluation distribution.

The external results are substantially lower than the internal results, particularly for rare R2L and U2R attack families.

This difference is important because it demonstrates the effect of:

* distribution shift
* class imbalance
* rare attack categories
* dataset-specific patterns

Therefore, the internal accuracy figures should **not** be interpreted as proof of equivalent real-world detection performance.

---

#  Application Architecture

```text
┌───────────────────────────────────────────────┐
│                 WEB CLIENT                    │
│        HTML / CSS / JavaScript                │
└───────────────────────┬───────────────────────┘
                        │
                        ▼
┌───────────────────────────────────────────────┐
│                 FASTAPI                       │
│             REST API / Routing                │
└───────────────────────┬───────────────────────┘
                        │
              ┌─────────┴──────────┐
              ▼                    ▼
      ┌───────────────┐    ┌────────────────┐
      │   Inference   │    │    Incident    │
      │    Engine     │    │    Registry    │
      └───────┬───────┘    └────────────────┘
              │
              ▼
      ┌────────────────┐
      │ Model Loader   │
      └───────┬────────┘
              │
       ┌──────┴──────┐
       ▼             ▼
   Stage 1 RF     Stage 2 RF
       │             │
       └──────┬──────┘
              ▼
        Security Verdict
```

---

#  Project Structure

```text
CSNet-IDA/
│
├── app/
│   ├── main.py
│   ├── templates/
│   │   └── index.html
│   └── static/
│       ├── css/
│       │   └── style.css
│       └── js/
│           └── app.js
│
├── data/
│   └── raw/
│
├── models/
│   ├── random_forest_final.pkl
│   ├── preprocessor_final.pkl
│   ├── threshold_final.pkl
│   ├── attack_family_random_forest_final.pkl
│   ├── attack_family_labels_final.pkl
│   └── intrusion_detection_two_stage_final.pkl
│
├── notebooks/
│   └── 01_data_exploration.ipynb
│
├── results/
│   ├── figures/
│   └── reports/
│
├── src/
│   ├── inference.py
│   ├── model_loader.py
│   ├── incidents.py
│   ├── simulation.py
│   ├── explainability.py
│   └── schemas.py
│
├── tests/
│
├── requirements.txt
├── run_app.py
├── .gitignore
└── README.md
```

---

#  Technology Stack

### Machine Learning

* Python
* Scikit-learn
* Random Forest
* Pandas
* NumPy
* Joblib

### Backend

* FastAPI
* Uvicorn
* Pydantic
* Jinja2

### Frontend

* HTML5
* CSS3
* JavaScript
* Canvas-based telemetry visualization

### Research & Evaluation

* Jupyter Notebook
* Matplotlib
* Seaborn
* NSL-KDD
* KDDTest+

### Deployment

* GitHub
* Render

---

#  Run Locally

Clone the repository:

```bash
git clone https://github.com/sumaiya-ds/CSNet-IDA.git
cd CSNet-IDA
```

Create the Conda environment:

```bash
conda create -n data-science python=3.11
conda activate data-science
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Start the application:

```bash
python run_app.py
```

Then open:

```text
http://127.0.0.1:8000
```

---

#  Deployed Application

The current prototype is publicly deployed through Render:

**https://csnet-ida.onrender.com/**

The deployment exposes the same two-stage inference pipeline and SOC interface used by the local application.

---

#  Limitations

CSNet-IDA is a research/prototype IDS rather than a production network sensor.

Important limitations include:

* The system operates on structured network connection features rather than directly capturing packets.
* NSL-KDD is an established benchmark dataset but does not represent the full complexity of modern enterprise traffic.
* R2L and U2R contain comparatively few samples.
* Model performance can degrade under distribution shift.
* Simulation scenarios are deterministic demonstrations and should not be interpreted as live threat intelligence.
* The current application does not replace a production SIEM, IDS, firewall, EDR, or packet-analysis system.

These limitations are intentionally documented to distinguish benchmark performance from real-world security performance.

---

#  Future Development

Planned improvements include:

* Real packet capture integration
* Streaming network telemetry
* Additional datasets
* Cross-dataset validation
* Improved rare-class handling
* Cost-sensitive learning
* Feature selection
* Hyperparameter optimization
* Advanced explainability
* Persistent incident storage
* Authentication and role-based access
* Production-grade alerting
* Containerized deployment
* Automated CI/CD testing

---

#  Research Context

CSNet-IDA was developed as a machine-learning and cybersecurity project exploring how a benchmark intrusion detection model can be extended into an interactive security intelligence application.

The project focuses on the complete path:

```text
DATA
 ↓
PREPROCESSING
 ↓
MODEL
 ↓
INFERENCE
 ↓
SECURITY DECISION
 ↓
INCIDENT
 ↓
INVESTIGATION
 ↓
VISUALIZATION
```

This makes the project more than a standalone classifier: the trained ML pipeline is integrated into an operational prototype that allows its decisions to be inspected and demonstrated.

---

#  Author

**Shaik Sumaiya Sultana**

Data Science Student

GitHub:
https://github.com/sumaiya-ds

---

## License

This project is intended primarily for academic, research, and educational purposes.

See the repository license for applicable usage terms.

---

##  Project Status

**Current status: Deployed Prototype**

The current implementation includes:

* Two-stage Random Forest IDS
* NSL-KDD-based inference
* FastAPI backend
* SOC command center
* Live simulation engine
* Security telemetry
* Incident management
* Investigation workstation
* Connection inspector
* Explainability components
* Interactive demonstration workflow
* Public Render deployment

Further ML intelligence, evaluation, interface refinement, and deployment improvements remain planned.
