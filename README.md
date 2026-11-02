# 🛡️ AegisMail AI — Enterprise Email Spam & Threat Defense System

**AegisMail AI** is a senior-grade, full-stack NLP web application built to detect, classify, and isolate malicious email spam and phishing threats in real time. Powered by **Multinomial Naive Bayes**, **spaCy** morphological lemmatization, and **n-gram feature extraction**, the system delivers **98.2% accuracy** on unseen test data with full explainable feature attribution (log likelihood ratios).

---

## 🌟 Key Features

1. **⚡ Live Email Threat Scanner & Explainable AI**:
   - Real-time classification into **Clean (Ham)**, **Suspicious**, or **Critical Spam**.
   - Instant 1-click test presets (*PayPal Phishing Alert*, *Lottery Scam*, *Office 365 Credential Harvester*, *Corporate Sprint Meeting*, *Amazon Order Confirmation*).
   - **Explainable Feature Attribution**: Inspects exact tokens/n-grams (e.g. `claim`, `prize`, `award`, `urgent`, `guarantee`) that influenced the Naive Bayes posterior decision via log likelihood ratios ($\log P(w|\text{spam}) - \log P(w|\text{ham})$).
   - **Heuristic Threat Engine**: Automatically flags psychological urgency, credential harvesting patterns, suspicious high-risk TLDs (`.xyz`, `.biz`, `.top`), and brand spoofing.
   - Dual animated probability bars and dynamic risk badges.

2. **📦 Quarantine Vault & Incident Management**:
   - Automated isolation of malicious threats into SQLite (`data/emails.db`) and persistent CSV archive (`data/quarantine/quarantine.csv`).
   - Real-time search by sender, subject, or message keyword.
   - Filter by active quarantine vs released items.
   - Incident Inspector modal with sanitized previews and header analytics.
   - 1-click **Release to Inbox** and **Export to CSV**.

3. **📊 Batch Email Threat Scanner**:
   - Upload `.csv` or `.txt` datasets, or paste hundreds of emails directly.
   - Multi-threaded processing with animated progress tracking.
   - Executive batch summary metrics: *Total Audited*, *Spam Blocked*, *Clean Verified*, and *Threat Rate %*.

4. **🧬 Model Architecture & 8-Stage Pipeline Explorer**:
   - Interactive visual walkthrough detailing each stage of model development:
     - **Stage 1**: Data Ingestion (`data/raw/email_spam_dataset.csv`, 5,572 samples).
     - **Stage 2**: NLP Lemmatization & Regex Cleaning (`src/data/preprocess.py`, spaCy `en_core_web_sm`).
     - **Stage 3**: Batched Corpus Preprocessing (`src/data/process_dataset.py`).
     - **Stage 4**: CountVectorizer Feature Extraction (5,000 max features, unigram + bigram pairs).
     - **Stage 5**: Multinomial Naive Bayes Model Definition ($\alpha=1.0$ Laplace smoothing).
     - **Stage 6**: Stratified Model Training (`src/models/train.py`, 80/20 train/test split).
     - **Stage 7**: Model Evaluation & Confusion Matrix (`src/models/evaluate.py`).
     - **Stage 8**: Class Imbalance Benchmark (`src/models/optimize.py`, RandomOverSampler).
   - Interactive Confusion Matrix widget (134 True Positives, 961 True Negatives, 5 False Positives, 15 False Negatives).
   - Top discriminative vocabulary n-gram clouds for spam vs ham.

5. **📈 Executive Threat Analytics & KPIs**:
   - Real-time KPIs: *Total Emails Audited*, *Spam Threats Blocked*, *Clean Inflow Verified*, *Detection Rate %*.
   - Dynamic **Chart.js** visualizations: Threat Distribution Doughnut Chart & Top Trigger Keywords Bar Chart.

6. **⚙️ Security Sandbox & Custom Rules Engine**:
   - Live sensitivity threshold slider (Aggressive $\leftrightarrow$ Balanced $\leftrightarrow$ Conservative).
   - Custom whitelist / blacklist rule builder (domains, senders, custom keyword triggers).

---

## 🔬 Model Performance & Validation

Evaluated on 1,115 test samples (80/20 stratified split from 5,572 emails):

| Metric | Score |
| :--- | :--- |
| **Overall Accuracy** | **98.2%** |
| **Spam Precision** | **96%** |
| **Spam Recall** | **90%** |
| **Spam F1-Score** | **93%** |
| **Ham Precision** | **98%** |
| **Ham Recall** | **99%** |
| **Ham F1-Score** | **99%** |

### Confusion Matrix (Test Split: 1,115 Samples)
```
                    Predicted Spam      Predicted Ham
Actual Spam              134                 15 (False Negative)
Actual Ham                 5 (False Positive) 961
```

---

## 🚀 How to Run Locally

### 1. Launch the Server
From the project root:
```bash
python main.py
```
Or directly using Uvicorn:
```bash
uvicorn src.api.app:app --host 127.0.0.1 --port 8000 --reload
```

### 2. Access the Application
Open your web browser and navigate to:
```
http://127.0.0.1:8000
```
Interactive Swagger API documentation is available at:
```
http://127.0.0.1:8000/docs
```

---

## 📡 REST API Reference

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/` | `GET` | Serves the single-page application |
| `/api/scan` | `POST` | Inspect single email with NLP explainability & heuristics |
| `/predict` | `POST` | Legacy endpoint returning `{"label": "..."}` |
| `/api/scan-batch` | `POST` | Batch process multiple emails |
| `/api/quarantine` | `GET` | List quarantined threats with search & status filters |
| `/api/quarantine/{id}/release` | `POST` | Release an email back to the inbox |
| `/api/quarantine/{id}` | `DELETE` | Permanently purge a quarantine record |
| `/api/quarantine/export` | `GET` | Download quarantine archive as CSV |
| `/api/analytics` | `GET` | Retrieve KPI metrics and threat distribution data |
| `/api/model-info` | `GET` | Return pipeline architecture, stages, & top vocabulary |
| `/api/rules` | `GET` / `POST` | Manage custom whitelist/blacklist security rules |
| `/api/rules/{id}` | `DELETE` | Delete custom security rule |

"# Email-Spam-Ham-Classification" 
