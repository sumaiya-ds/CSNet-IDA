# CSNet-IDA

## Intrusion Detection System Using a Two-Stage Random Forest Architecture

CSNet-IDA is a machine-learning-based Intrusion Detection System (IDS) designed to identify malicious network traffic and classify detected attacks into their corresponding attack families.

The system uses a two-stage classification architecture:

1. **Stage 1 — Binary Detection**

   * Classifies network traffic as `Normal` or `Attack`.
   * Uses a Random Forest classifier.
   * Uses a configurable probability threshold for attack detection.

2. **Stage 2 — Attack Family Classification**

   * Applied to traffic identified as an attack.
   * Classifies attacks into:

     * DoS
     * Probe
     * R2L
     * U2R

## Dataset

The project uses the NSL-KDD dataset.

The dataset contains network connection records represented by 41 attributes, including:

* Duration
* Protocol type
* Service
* Flag
* Source and destination bytes
* Connection statistics
* Host-based traffic statistics

The raw dataset files are intentionally excluded from this repository.

## Architecture

```text
Network Traffic
       |
       v
Data Preprocessing
       |
       v
Stage 1: Random Forest
       |
       +------------------+
       |                  |
     Normal              Attack
       |                  |
       v                  v
    NORMAL        Stage 2: Random Forest
                         |
             +-----------+-----------+-----------+
             |           |           |           |
            DoS        Probe        R2L         U2R
```

## Preprocessing

Categorical network features are transformed using a fitted `ColumnTransformer` with one-hot encoding.

The preprocessing pipeline converts the original 40 input features into 120 processed features for the Random Forest models.

The same fitted preprocessing pipeline is reused during inference.

## Stage 1 — Binary Classification

The Stage 1 Random Forest classifier was evaluated on the held-out internal test set.

### Results

| Metric    |  Score |
| --------- | -----: |
| Accuracy  | 99.93% |
| Precision | 99.90% |
| Recall    | 99.92% |
| F1 Score  | 99.91% |

Confusion Matrix:

```text
[[13457    12]
 [    9 11717]]
```

The final saved model uses an attack probability threshold of approximately `0.40`.

## Stage 2 — Attack Family Classification

Stage 2 was trained using attack samples and classifies them into four attack families.

### Internal Evaluation

| Attack Family | Precision | Recall |   F1 |
| ------------- | --------: | -----: | ---: |
| DoS           |      1.00 |   1.00 | 1.00 |
| Probe         |      1.00 |   1.00 | 1.00 |
| R2L           |      1.00 |   0.99 | 1.00 |
| U2R           |      0.75 |   1.00 | 0.86 |

Overall internal accuracy:

**99.98%**

The relatively small number of U2R samples should be considered when interpreting its metrics.

## End-to-End Classification

The complete system operates as follows:

```text
Input Network Connection
          |
          v
     Preprocessing
          |
          v
   Stage 1 Classifier
          |
     +----+----+
     |         |
  Normal     Attack
     |         |
     v         v
  NORMAL   Stage 2 Classifier
                |
        +-------+-------+-------+
        |       |       |       |
       DoS    Probe    R2L     U2R
```

This design separates the initial detection problem from the more specific attack-family classification problem.

## Project Structure

```text
CSNet-IDA/
│
├── data/
│   └── raw/                  # Dataset files (excluded from Git)
│
├── notebooks/
│   └── 01_data_exploration.ipynb
│
├── models/                   # Model artifacts
│
├── results/
│   ├── figures/
│   └── reports/
│
├── src/                      # Source code
│
├── app/                      # Application layer
│
├── .gitignore
├── requirements.txt
└── README.md
```

## Installation

Create and activate the Conda environment:

```bash
conda create -n data-science python=3.11
conda activate data-science
```

Install the required packages:

```bash
pip install -r requirements.txt
```

## Running the Notebook

Start Jupyter:

```bash
jupyter notebook
```

Open:

```text
notebooks/01_data_exploration.ipynb
```

Run the notebook cells sequentially.

## Saved Model Components

The trained system consists of:

* Random Forest binary classifier
* Feature preprocessing pipeline
* Detection threshold
* Attack-family Random Forest classifier
* Attack-family label mapping

Large serialized model files are excluded from GitHub using `.gitignore`.

## Limitations

The internal evaluation results are based on the held-out evaluation split used during model development.

Performance on an external NSL-KDD test distribution can differ substantially because of distribution shift and differences between the training and external test distributions.

Therefore, the reported internal metrics should not be interpreted as universal real-world IDS performance.

## Future Improvements

* Improve generalization to unseen network traffic.
* Address class imbalance in rare attack families such as R2L and U2R.
* Evaluate additional machine-learning algorithms.
* Investigate feature selection and dimensionality reduction.
* Add real-time network packet ingestion.
* Develop a web-based monitoring dashboard.
* Add alert generation and attack logging.
* Perform cross-dataset validation.

## Technologies

* Python
* Pandas
* NumPy
* Scikit-learn
* Random Forest
* Jupyter Notebook
* Joblib
* Matplotlib
* Seaborn
