import csv
import os
from datetime import datetime
from typing import List, Dict

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
QUARANTINE_DIR = os.path.join(BASE_DIR, "data", "quarantine")
QUARANTINE_FILE = os.path.join(QUARANTINE_DIR, "quarantine.csv")


def quarantine_email(email_text: str, label: str):
    os.makedirs(QUARANTINE_DIR, exist_ok=True)

    new_file = not os.path.exists(QUARANTINE_FILE)

    with open(QUARANTINE_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if new_file:
            writer.writerow(["timestamp", "label", "email_text"])

        writer.writerow([datetime.now().isoformat(), label, email_text])


def read_quarantine_csv() -> List[Dict[str, str]]:
    if not os.path.exists(QUARANTINE_FILE):
        return []

    records = []
    with open(QUARANTINE_FILE, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for row in reader:
            records.append(row)
    return records
