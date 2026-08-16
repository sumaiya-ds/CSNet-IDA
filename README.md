# CSNet-IDA

## Two-Stage Machine Learning Intrusion Detection System

CSNet-IDA is a machine-learning-based Intrusion Detection System (IDS) designed to detect malicious network traffic and classify detected attacks into their respective attack families.

The system uses a **two-stage Random Forest architecture**:

* **Stage 1:** Binary classification — Normal vs Attack
* **Stage 2:** Attack-family classification — DoS, Probe, R2L, and U2R

The project is developed using the NSL-KDD dataset and implemented in Python using Scikit-learn.

---

## System Architecture

```text
                    NETWORK CONNECTION
                            |
                            v
                  FEATURE PREPROCESSING
                            |
                            v
                +-----------------------+
                |       STAGE 1         |
                |   Binary Classifier   |
                |    Random Forest      |
                +-----------------------+
                     /             \
                    /               \
                   v                 v
              NORMAL              ATTACK
                                    |
                                    v
                          +-------------------+
                          |      STAGE 2      |
                          | Attack Classifier |
                          |   Random Forest   |
                          +-------------------+
                            /    |    |    \
                           /     |    |     \
                          v      v    v      v
                         DoS   Probe  R2L    U2R
```

---

## Dataset

CSNet-IDA uses the **NSL-KDD** benchmark dataset for network intrusion detection.

The dataset contains network connection records represented using 41 attributes, including:

* Duration
* Protocol type
* Service
* Connection flag
* Source and destination bytes
* Login and privilege-related features
* Connection statistics
* Host-based traffic statistics

The raw dataset is **not included in this repository**.

---

## Attack Families

The attack labels are grouped into four major attack families:

| Family | Example Attacks                                                                             |
| ------ | ------------------------------------------------------------------------------------------- |
| DoS    | `back`, `land`, `neptune`, `pod`, `smurf`, `teardrop`                                       |
| Probe  | `ipsweep`, `nmap`, `portsweep`, `satan`                                                     |
| R2L    | `ftp_write`, `guess_passwd`, `imap`, `multihop`, `phf`, `spy`, `warezclient`, `warezmaster` |
| U2R    | `buffer_overflow`, `loadmodule`, `perl`, `rootkit`                                          |

Normal traffic is handled separately by Stage 1.

---

## Preprocessing

The input data contains both numerical and categorical features.

Categorical features such as:

* `protocol_type`
* `service`
* `flag`

are encoded using a fitted Scikit-learn preprocessing pipeline.

The original **40 input features** are transformed into **120 processed features**.

The same fitted preprocessing pipeline is reused during inference to maintain consistency between training and prediction.

---

# Stage 1 — Binary Attack Detection

Stage 1 determines whether a network connection is:

```text
Normal
   or
Attack
```

A Random Forest classifier is used for the binary detection task.

### Internal Test Results

| Metric        |     Result |
| ------------- | ---------: |
| Accuracy      | **99.93%** |
| Normal Recall | **99.94%** |
| Attack Recall | **99.91%** |

Confusion Matrix:

```text
                 Predicted
               Normal  Attack

Actual Normal    13461      8
Actual Attack       10  11716
```

The final model uses a configurable attack probability threshold.

---

# Stage 2 — Attack Family Classification

Traffic classified as an attack by Stage 1 is passed to Stage 2.

Stage 2 classifies the attack into:

* DoS
* Probe
* R2L
* U2R

### Internal Test Results

| Attack Family | Precision | Recall |   F1 |
| ------------- | --------: | -----: | ---: |
| DoS           |      1.00 |   1.00 | 1.00 |
| Probe         |      1.00 |   1.00 | 1.00 |
| R2L           |      1.00 |   0.99 | 1.00 |
| U2R           |      0.75 |   1.00 | 0.86 |

Overall Stage 2 accuracy:

**99.98%**

The U2R class contains very few samples, so its metrics should be interpreted with caution.

---

# End-to-End IDS

The complete inference pipeline is:

```text
Raw Network Features
        |
        v
Preprocessing
        |
        v
Stage 1 Random Forest
        |
        +------------------+
        |                  |
        v                  v
     Normal              Attack
        |                  |
        v                  v
     NORMAL        Stage 2 Random Forest
                          |
              +-----------+-----------+
              |           |           |
             DoS        Probe        R2L
                                      |
                                      U2R
```

This hierarchical architecture separates **attack detection** from **attack-family identification**.

---

## Model Files

The trained models are stored in the `models/` directory.

| File                                      | Purpose                        |
| ----------------------------------------- | ------------------------------ |
| `random_forest_final.pkl`                 | Stage 1 binary classifier      |
| `preprocessor_final.pkl`                  | Feature preprocessing pipeline |
| `threshold_final.pkl`                     | Stage 1 decision threshold     |
| `attack_family_random_forest_final.pkl`   | Stage 2 classifier             |
| `attack_family_labels_final.pkl`          | Stage 2 label mapping          |
| `intrusion_detection_two_stage_final.pkl` | Combined IDS artifact          |

---

## Project Structure

```text
CSNet-IDA/
│
├── app/
│
├── data/
│   └── raw/
│       └── Dataset files are excluded from Git
│
├── models/
│   ├── attack_family_labels_final.pkl
│   ├── attack_family_random_forest_final.pkl
│   ├── intrusion_detection_two_stage_final.pkl
│   ├── preprocessor_final.pkl
│   ├── random_forest_final.pkl
│   └── threshold_final.pkl
│
├── notebooks/
│   └── 01_data_exploration.ipynb
│
├── results/
│   ├── figures/
│   └── reports/
│
├── src/
│
├── .gitignore
├── README.md
└── requirements.txt
```

---

## Installation

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

---

## Running the Project

Start Jupyter Notebook:

```bash
jupyter notebook
```

Open:

```text
notebooks/01_data_exploration.ipynb
```

Run the notebook cells sequentially.

The notebook contains the data exploration, preprocessing, model development, evaluation, and IDS experimentation workflow.

---

## Evaluation Strategy

The project separates:

### Training

Model training is performed using the training portion of the NSL-KDD data.

### Internal Evaluation

A held-out test split is used during development to evaluate the trained models.

### External Validation

The KDDTest+ dataset was also evaluated separately to investigate generalization to an external test distribution.

The external evaluation produced substantially lower performance, particularly for the rare R2L and U2R attack families.

This behavior highlights the difference between strong performance on an internal held-out distribution and generalization to a separate benchmark distribution.

The external evaluation is therefore treated as a **generalization experiment rather than the primary headline result**.

---

## Limitations

Several limitations remain:

* Strong class imbalance exists among attack families.
* R2L and U2R contain relatively few training examples.
* Performance can change significantly under distribution shift.
* The current system operates on pre-extracted network connection features rather than directly capturing live packets.
* The current implementation does not yet provide a complete real-time monitoring interface.

---

## Future Work

Potential improvements include:

* Real-time packet capture and inference
* Improved handling of rare attack classes
* Cost-sensitive learning
* Class-weighted and ensemble approaches
* Feature selection
* Hyperparameter optimization
* Cross-dataset evaluation
* Explainable AI for intrusion predictions
* Real-time alert generation
* Web-based IDS monitoring dashboard
* Attack logging and visualization

---

## Technologies

* Python
* Pandas
* NumPy
* Scikit-learn
* Random Forest
* Joblib
* Jupyter Notebook
* Matplotlib
* Seaborn

---

## Project Status

**Completed prototype / research implementation**

The current implementation demonstrates a two-stage machine-learning IDS pipeline with trained models, preprocessing artifacts, evaluation workflow, and external validation experiments.
