import os
import re
import joblib
import numpy as np
from typing import Dict, Any, List, Optional
from src.data.preprocess import clean_text
from src.data.db import get_rules, log_scan

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MODEL_PATH = os.path.join(BASE_DIR, "models", "spam_model.pkl")
VECTORIZER_PATH = os.path.join(BASE_DIR, "models", "count_vectorizer.pkl")

# Global cached singletons
_model = None
_vectorizer = None
_feature_names = None
_log_ratio = None


def load_model_and_vectorizer():
    global _model, _vectorizer, _feature_names, _log_ratio
    if _model is None or _vectorizer is None:
        if not os.path.exists(MODEL_PATH) or not os.path.exists(VECTORIZER_PATH):
            raise FileNotFoundError("Model or vectorizer pickle file not found in models/ directory.")
        _model = joblib.load(MODEL_PATH)
        _vectorizer = joblib.load(VECTORIZER_PATH)
        _feature_names = np.array(_vectorizer.get_feature_names_out())

        # MultinomialNB log prob classes: [0: ham, 1: spam]
        log_prob_ham = _model.feature_log_prob_[0]
        log_prob_spam = _model.feature_log_prob_[1]
        _log_ratio = log_prob_spam - log_prob_ham

    return _model, _vectorizer, _feature_names, _log_ratio


def extract_explainability_features(cleaned_text: str, top_k: int = 10) -> List[Dict[str, Any]]:
    """
    Extracts the key words/n-grams in the email that most strongly pushed
    the classification toward Spam or Ham based on Naive Bayes log likelihood ratios.
    """
    _, vectorizer, feature_names, log_ratio = load_model_and_vectorizer()

    # Transform current text
    x_sample = vectorizer.transform([cleaned_text])
    present_indices = x_sample.nonzero()[1]

    if len(present_indices) == 0:
        return []

    ratios = log_ratio[present_indices]
    words = feature_names[present_indices]

    # Sort by ratio descending (highest positive = strongest spam indicators)
    sorted_order = np.argsort(ratios)[::-1]

    top_features = []
    for idx in sorted_order[:top_k]:
        score = float(ratios[idx])
        top_features.append({
            "word": str(words[idx]),
            "score": round(score, 3),
            "leans": "spam" if score > 0 else "ham",
            "impact": "High" if abs(score) >= 2.5 else "Medium"
        })

    return top_features


def analyze_security_heuristics(sender: str, subject: str, body: str) -> List[Dict[str, str]]:
    """
    Scans for signature security threats, phishing lures, and deceptive patterns.
    """
    combined = f"{subject} {body}".lower()
    signals = []

    # Phishing / URL heuristics
    urls = re.findall(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", f"{subject} {body}")
    if urls:
        suspicious_urls = [u for u in urls if any(tld in u.lower() for tld in [".xyz", ".biz", ".top", ".club", ".info", ".ru", ".tk"])]
        if suspicious_urls:
            signals.append({
                "type": "Malicious Domain Pattern",
                "detail": f"Contains link with high-risk TLD: {suspicious_urls[0]}",
                "severity": "CRITICAL"
            })
        else:
            signals.append({
                "type": "External Links Detected",
                "detail": f"Found {len(urls)} external URL link(s) in message body",
                "severity": "WARNING"
            })

    # Urgency & Panic Induction
    urgency_keywords = ["urgent", "immediately", "account suspended", "action required", "24 hours", "final notice", "unauthorized access", "terminate"]
    found_urgency = [k for k in urgency_keywords if k in combined]
    if found_urgency:
        signals.append({
            "type": "Psychological Urgency Indicator",
            "detail": f"Triggers immediate panic reaction: '{', '.join(found_urgency[:3])}'",
            "severity": "HIGH"
        })

    # Financial / Lottery Lures
    financial_keywords = ["lottery", "cash prize", "million dollars", "claim prize", "winner", "wire transfer", "bitcoin", "crypto", "free gift card", "payout", "inheritance"]
    found_financial = [k for k in financial_keywords if k in combined]
    if found_financial:
        signals.append({
            "type": "Financial Lure / Advance-Fee Pattern",
            "detail": f"Monetary reward hooks detected: '{', '.join(found_financial[:3])}'",
            "severity": "CRITICAL"
        })

    # Credential Harvesting Hooks
    cred_keywords = ["password", "verify credentials", "ssn", "social security", "pin number", "login here", "billing portal", "security alert"]
    found_creds = [k for k in cred_keywords if k in combined]
    if found_creds:
        signals.append({
            "type": "Credential Harvesting Indicator",
            "detail": f"Requests sensitive user authentication: '{', '.join(found_creds[:3])}'",
            "severity": "HIGH"
        })

    # Excessive Capitalization / Shout casing
    capitals = sum(1 for c in body if c.isupper())
    total_letters = sum(1 for c in body if c.isalpha())
    if total_letters > 20 and (capitals / total_letters) > 0.40:
        signals.append({
            "type": "Excessive Capitalization",
            "detail": f"Unusually high capital letter ratio ({round((capitals/total_letters)*100)}%) signaling aggressive spam behavior",
            "severity": "MEDIUM"
        })

    # Spoofed Sender Check
    if sender:
        sender_lower = sender.lower()
        if any(name in sender_lower for name in ["paypal", "microsoft", "google", "apple", "netflix", "bank", "amazon"]):
            if not any(sender_lower.endswith(trusted) for trusted in ["@paypal.com", "@microsoft.com", "@google.com", "@apple.com", "@netflix.com", "@amazon.com"]):
                signals.append({
                    "type": "Brand Spoofing / Impersonation",
                    "detail": f"Sender address '{sender}' attempts brand impersonation from untrusted domain",
                    "severity": "CRITICAL"
                })

    return signals


def evaluate_custom_rules(sender: str, subject: str, body: str) -> Optional[Dict[str, Any]]:
    """
    Checks user-defined whitelist and blacklist rules.
    """
    rules = get_rules()
    sender_clean = sender.strip().lower()
    content = f"{subject} {body}".lower()

    for r in rules:
        rtype = r["rule_type"]
        val = r["value"]
        action = r["action"]

        if rtype == "whitelist_sender" and sender_clean == val:
            return {"override": True, "label": "ham", "reason": f"Whitelisted sender: {val}"}
        if rtype == "blacklist_sender" and sender_clean == val:
            return {"override": True, "label": "spam", "reason": f"Blacklisted sender: {val}"}
        if rtype == "whitelist_domain" and sender_clean.endswith(f"@{val}"):
            return {"override": True, "label": "ham", "reason": f"Whitelisted domain: @{val}"}
        if rtype == "blacklist_domain" and sender_clean.endswith(f"@{val}"):
            return {"override": True, "label": "spam", "reason": f"Blacklisted domain: @{val}"}
        if rtype == "custom_keyword" and val in content:
            return {"override": True, "label": "spam" if action == "force_spam" else "ham", "reason": f"Keyword trigger match: '{val}'"}

    return None


def scan_email(sender: str, subject: str, body: str, sensitivity_threshold: float = 0.5) -> Dict[str, Any]:
    """
    Comprehensive full-stack inference pipeline:
    1. Preprocesses text (spaCy lemmatization + regex)
    2. Vectorizes (CountVectorizer 1-2 ngrams)
    3. Runs MultinomialNB prediction with adjustable sensitivity threshold
    4. Evaluates explainability features (top contributing n-grams)
    5. Analyzes security heuristics
    6. Checks custom whitelist/blacklist rules
    7. Computes composite threat score & risk tier
    8. Persists to SQLite + quarantine records if spam
    """
    model, vectorizer, _, _ = load_model_and_vectorizer()

    # Combine subject and body for realistic email inspection
    full_text = f"{subject}\n\n{body}" if subject else body
    cleaned = clean_text(full_text)

    # Transform
    x_features = vectorizer.transform([cleaned])

    # MultinomialNB class probabilities
    probabilities = model.predict_proba(x_features)[0]
    classes = list(model.classes_)

    ham_idx = classes.index("ham")
    spam_idx = classes.index("spam")

    raw_ham_prob = float(probabilities[ham_idx])
    raw_spam_prob = float(probabilities[spam_idx])

    # Explainability features
    top_features = extract_explainability_features(cleaned, top_k=8)

    # Security heuristics
    signals = analyze_security_heuristics(sender, subject, body)

    # Check custom rules
    rule_override = evaluate_custom_rules(sender, subject, body)

    if rule_override:
        label = rule_override["label"]
        spam_prob = 0.999 if label == "spam" else 0.001
        ham_prob = 1.0 - spam_prob
        rule_reason = rule_override["reason"]
        signals.insert(0, {"type": "Custom Security Rule", "detail": rule_reason, "severity": "HIGH"})
    else:
        # Decision based on sensitivity threshold
        if raw_spam_prob >= sensitivity_threshold:
            label = "spam"
        else:
            label = "ham"
        spam_prob = raw_spam_prob
        ham_prob = raw_ham_prob

    # Composite Threat Score (0 to 100)
    base_threat = spam_prob * 100
    heuristic_boost = len([s for s in signals if s["severity"] in ("CRITICAL", "HIGH")]) * 8
    threat_score = min(100, max(0, int(base_threat * 0.85 + heuristic_boost)))

    # Risk Tier categorization
    if label == "spam" or threat_score >= 70:
        risk_tier = "CRITICAL_SPAM"
    elif threat_score >= 35 or spam_prob >= 0.35:
        risk_tier = "SUSPICIOUS"
    else:
        risk_tier = "SAFE"

    # Log to SQLite and quarantine if spam
    indicator_strings = [f"{s['type']}: {s['detail']}" for s in signals]
    db_record = log_scan(
        sender=sender or "unknown@sender.com",
        subject=subject or "(No Subject)",
        body=body,
        cleaned_text=cleaned,
        label=label,
        spam_prob=round(spam_prob, 4),
        ham_prob=round(ham_prob, 4),
        risk_tier=risk_tier,
        threat_score=threat_score,
        indicators=indicator_strings,
        top_features=top_features
    )

    return {
        **db_record,
        "clean_email": cleaned,
        "heuristic_signals": signals,
        "threshold_used": sensitivity_threshold,
        "rule_override": rule_override is not None
    }


def scan_batch(emails: List[Dict[str, str]], sensitivity_threshold: float = 0.5) -> Dict[str, Any]:
    """
    Processes a batch of emails.
    """
    results = []
    spam_count = 0
    ham_count = 0

    for item in emails:
        sender = item.get("sender", "")
        subject = item.get("subject", "")
        body = item.get("body", item.get("text", ""))

        if not body.strip():
            continue

        res = scan_email(sender, subject, body, sensitivity_threshold)
        results.append(res)
        if res["label"] == "spam":
            spam_count += 1
        else:
            ham_count += 1

    total = len(results)
    threat_rate = round((spam_count / total * 100), 1) if total > 0 else 0.0

    return {
        "total_processed": total,
        "spam_detected": spam_count,
        "ham_verified": ham_count,
        "threat_rate": threat_rate,
        "results": results
    }


def get_pipeline_metadata() -> Dict[str, Any]:
    """
    Returns rich metadata detailing the 8-stage ML pipeline and performance stats.
    """
    _, _, feature_names, log_ratio = load_model_and_vectorizer()

    # Extract top 15 spam n-grams and top 15 ham n-grams
    top_spam_indices = np.argsort(log_ratio)[-15:][::-1]
    top_ham_indices = np.argsort(log_ratio)[:15]

    top_spam_vocab = [
        {"ngram": str(feature_names[i]), "log_ratio": round(float(log_ratio[i]), 3)}
        for i in top_spam_indices
    ]
    top_ham_vocab = [
        {"ngram": str(feature_names[i]), "log_ratio": round(float(log_ratio[i]), 3)}
        for i in top_ham_indices
    ]

    return {
        "model_name": "Multinomial Naive Bayes (MultinomialNB)",
        "vectorizer_name": "CountVectorizer (Unigrams & Bigrams)",
        "vocab_size": len(feature_names),
        "ngram_range": [1, 2],
        "smoothing_alpha": 1.0,
        "dataset_name": "SMS / Email Spam Collection Dataset",
        "dataset_samples": 5572,
        "train_test_split": "80% Train (4,457), 20% Test (1,115)",
        "metrics": {
            "overall_accuracy": 0.982,
            "spam_precision": 0.96,
            "spam_recall": 0.90,
            "spam_f1_score": 0.93,
            "ham_precision": 0.98,
            "ham_recall": 0.99,
            "ham_f1_score": 0.99,
        },
        "confusion_matrix": {
            "actual_spam_pred_spam": 134,
            "actual_spam_pred_ham": 15,
            "actual_ham_pred_spam": 5,
            "actual_ham_pred_ham": 961,
            "total_test": 1115
        },
        "stages": [
            {
                "stage": 1,
                "title": "Data Ingestion & Schema Alignment",
                "file": "src/data/load_data.py",
                "description": "Loads raw email collection (5,572 records), extracts v1 (label) and v2 (email_text), maps into standardized ham/spam columns."
            },
            {
                "stage": 2,
                "title": "NLP Lemmatization & Sanitization",
                "file": "src/data/preprocess.py",
                "description": "Applies lowercase conversion, URL stripping, non-alphabet regex filtering, and spaCy 'en_core_web_sm' morphological lemmatization + stop word removal."
            },
            {
                "stage": 3,
                "title": "Batched Corpus Pipeline Execution",
                "file": "src/data/process_dataset.py",
                "description": "Streams corpus through optimized spaCy nlp.pipe (parser & ner disabled) in 200-item chunks, exporting cleaned_emails.csv."
            },
            {
                "stage": 4,
                "title": "N-Gram Vocabulary Vectorization",
                "file": "src/features/vectorizer.py",
                "description": "Fits CountVectorizer with 5,000 maximum features and (1, 2) n-gram range, capturing single terms and powerful bigram pairs (e.g. 'free prize', 'urgent collection')."
            },
            {
                "stage": 5,
                "title": "Multinomial Naive Bayes Architecture",
                "file": "src/models/build_model.py",
                "description": "Instantiates MultinomialNB with Laplace additive smoothing parameter alpha=1.0, ensuring unseen vocabulary tokens never zero out posterior class probabilities."
            },
            {
                "stage": 6,
                "title": "Stratified Model Training",
                "file": "src/models/train.py",
                "description": "Splits 80/20 with stratified sampling preserving class distribution. Trains on 4,457 examples and serializes spam_model.pkl."
            },
            {
                "stage": 7,
                "title": "Holistic Evaluation & Matrix Validation",
                "file": "src/models/evaluate.py",
                "description": "Evaluates on 1,115 unseen test samples achieving 98.2% accuracy, 96% spam precision, and only 5 false positives out of 966 legitimate emails."
            },
            {
                "stage": 8,
                "title": "Class Imbalance Exploration",
                "file": "src/models/optimize.py",
                "description": "Benchmarks severe class imbalance scenarios using RandomOverSampler (imbalanced-learn) to contrast baseline and synthetic balancing behavior."
            }
        ],
        "top_spam_vocabulary": top_spam_vocab,
        "top_ham_vocabulary": top_ham_vocab
    }

