import uvicorn
import sys
import os

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

if __name__ == "__main__":
    banner = """
======================================================================
  [+] AEGISMAIL AI - ENTERPRISE EMAIL SPAM & THREAT DEFENSE SYSTEM
======================================================================
  * Model:           Multinomial Naive Bayes (alpha=1.0)
  * Vectorizer:      CountVectorizer (5,000 max features, 1-2 n-grams)
  * NLP Engine:      spaCy Lemmatization (en_core_web_sm)
  * Accuracy:        98.2% on Test Split | 96% Spam Precision
  * Storage:         SQLite (data/emails.db) & CSV (data/quarantine/)
  
  >> Starting Web Server...
  >> Web Interface:  http://127.0.0.1:8000
  >> API Docs:       http://127.0.0.1:8000/docs
======================================================================
    """
    print(banner)
    uvicorn.run("src.api.app:app", host="127.0.0.1", port=8000, reload=False)
