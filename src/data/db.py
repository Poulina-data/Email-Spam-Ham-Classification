import sqlite3
import os
import json
from datetime import datetime
from typing import Dict, Any, List, Optional

DB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "data")
DB_PATH = os.path.join(DB_DIR, "emails.db")
QUARANTINE_CSV_PATH = os.path.join(DB_DIR, "quarantine", "quarantine.csv")


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    os.makedirs(DB_DIR, exist_ok=True)
    os.makedirs(os.path.join(DB_DIR, "quarantine"), exist_ok=True)

    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Table for all scanned emails
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                sender TEXT,
                subject TEXT,
                body TEXT NOT NULL,
                cleaned_text TEXT,
                label TEXT NOT NULL,
                spam_probability REAL NOT NULL,
                ham_probability REAL NOT NULL,
                risk_tier TEXT NOT NULL,
                threat_score INTEGER NOT NULL,
                indicators TEXT,
                top_features TEXT,
                is_quarantined INTEGER DEFAULT 0,
                user_feedback TEXT DEFAULT NULL
            )
        """)

        # Table for quarantine vault
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS quarantine (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                timestamp TEXT NOT NULL,
                sender TEXT,
                subject TEXT,
                body TEXT NOT NULL,
                spam_probability REAL NOT NULL,
                risk_tier TEXT NOT NULL,
                status TEXT DEFAULT 'QUARANTINED',
                reason TEXT
            )
        """)

        # Table for custom security rules
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_type TEXT NOT NULL,
                value TEXT NOT NULL,
                action TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)

        conn.commit()

        # Seed sample quarantined threats if table is brand new/empty
        cursor.execute("SELECT COUNT(*) FROM quarantine")
        if cursor.fetchone()[0] == 0:
            seed_initial_data(conn)


# Automatically ensure DB tables are initialized on import
try:
    init_db()
except Exception as _e:
    pass



def seed_initial_data(conn: sqlite3.Connection):
    samples = [
        {
            "sender": "account-security@verify-paypal-service.com",
            "subject": "URGENT: Your account has been suspended! Verify your credentials immediately",
            "body": "Dear customer, your PayPal account has experienced unusual login attempts. Click here: http://paypal-secure-verify.biz to claim your verification code immediately or your funds will be frozen within 24 hours.",
            "cleaned_text": "dear customer paypal account experience unusual login attempt click claim verification code immediately fund freeze hour",
            "label": "spam",
            "spam_probability": 0.985,
            "ham_probability": 0.015,
            "risk_tier": "CRITICAL_SPAM",
            "threat_score": 98,
            "indicators": json.dumps(["Urgent action phrasing", "External phishing link pattern", "Account suspension threat", "Financial manipulation"]),
            "top_features": json.dumps([{"word": "claim", "score": 4.12}, {"word": "urgent", "score": 3.85}, {"word": "code", "score": 2.94}]),
            "reason": "High confidence phishing & financial spoofing heuristics"
        },
        {
            "sender": "winner-dispatch@lottery-intl-promos.org",
            "subject": "CONGRATULATIONS! You have won $1,500,000 in the National Sweepstakes",
            "body": "Congratulations lucky winner! Your email has won award prize cash of $1,500,000. Contact our collection agent to claim guarantee prize ringtone mob tcs await collection.",
            "cleaned_text": "congratulation lucky winner email win award prize cash contact collection agent claim guarantee prize ringtone mob tcs await collection",
            "label": "spam",
            "spam_probability": 0.994,
            "ham_probability": 0.006,
            "risk_tier": "CRITICAL_SPAM",
            "threat_score": 99,
            "indicators": json.dumps(["Lottery award keywords", "Cash payout promise", "Urgent collection prompt"]),
            "top_features": json.dumps([{"word": "prize", "score": 5.21}, {"word": "claim", "score": 4.90}, {"word": "award", "score": 4.45}, {"word": "guarantee", "score": 3.78}]),
            "reason": "MultinomialNB spam triggers (prize, claim, award, collection)"
        },
        {
            "sender": "noreply-it-support@corp-secureauth-portal.net",
            "subject": "ACTION REQUIRED: Office 365 Password Expiry Alert",
            "body": "Your corporate email credentials expire today. Retain your current password by authenticating at our remote webmail portal immediately: http://login-microsoft-portal.xyz/verify",
            "cleaned_text": "corporate email credential expire today retain current password authenticate remote webmail portal immediately",
            "label": "spam",
            "spam_probability": 0.923,
            "ham_probability": 0.077,
            "risk_tier": "CRITICAL_SPAM",
            "threat_score": 92,
            "indicators": json.dumps(["Credential harvesting pattern", "External fake domain", "Urgent password expiry"]),
            "top_features": json.dumps([{"word": "urgent", "score": 3.42}, {"word": "expire", "score": 2.89}, {"word": "service", "score": 2.15}]),
            "reason": "Suspicious authentication harvester pattern"
        },
        {
            "sender": "sarah.jenkins@acme-enterprises.com",
            "subject": "Q4 Sprint Planning & Architecture Review Notes",
            "body": "Hi team, please find attached the meeting minutes and tickets for the upcoming sprint. Let's sync tomorrow at 10 AM to review the API integration progress.",
            "cleaned_text": "hi team find attach meeting minute ticket upcoming sprint let sync tomorrow review api integration progress",
            "label": "ham",
            "spam_probability": 0.0001,
            "ham_probability": 0.9999,
            "risk_tier": "SAFE",
            "threat_score": 1,
            "indicators": json.dumps(["Normal corporate communication"]),
            "top_features": json.dumps([{"word": "team", "score": -2.8}, {"word": "meeting", "score": -3.2}, {"word": "tomorrow", "score": -3.7}]),
            "reason": "Clean professional correspondence"
        }
    ]

    cursor = conn.cursor()
    for s in samples:
        cursor.execute("""
            INSERT INTO scans (
                timestamp, sender, subject, body, cleaned_text, label,
                spam_probability, ham_probability, risk_tier, threat_score,
                indicators, top_features, is_quarantined
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            datetime.now().isoformat(), s["sender"], s["subject"], s["body"], s["cleaned_text"],
            s["label"], s["spam_probability"], s["ham_probability"], s["risk_tier"], s["threat_score"],
            s["indicators"], s["top_features"], 1 if s["label"] == "spam" else 0
        ))
        scan_id = cursor.lastrowid

        if s["label"] == "spam":
            cursor.execute("""
                INSERT INTO quarantine (
                    scan_id, timestamp, sender, subject, body,
                    spam_probability, risk_tier, status, reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'QUARANTINED', ?)
            """, (
                scan_id, datetime.now().isoformat(), s["sender"], s["subject"], s["body"],
                s["spam_probability"], s["risk_tier"], s["reason"]
            ))

    # Add default rules
    default_rules = [
        ("blacklist_domain", "lottery-intl-promos.org", "force_spam", datetime.now().isoformat()),
        ("blacklist_domain", "paypal-secure-verify.biz", "force_spam", datetime.now().isoformat()),
        ("whitelist_domain", "company.internal", "force_ham", datetime.now().isoformat()),
        ("custom_keyword", "100% free guaranteed prize", "force_spam", datetime.now().isoformat()),
    ]
    cursor.executemany("INSERT INTO rules (rule_type, value, action, created_at) VALUES (?, ?, ?, ?)", default_rules)
    conn.commit()


def log_scan(
    sender: str,
    subject: str,
    body: str,
    cleaned_text: str,
    label: str,
    spam_prob: float,
    ham_prob: float,
    risk_tier: str,
    threat_score: int,
    indicators: List[str],
    top_features: List[Dict[str, Any]]
) -> Dict[str, Any]:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        now = datetime.now().isoformat()
        is_quarantined = 1 if label == "spam" else 0

        cursor.execute("""
            INSERT INTO scans (
                timestamp, sender, subject, body, cleaned_text, label,
                spam_probability, ham_probability, risk_tier, threat_score,
                indicators, top_features, is_quarantined
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            now, sender, subject, body, cleaned_text, label,
            spam_prob, ham_prob, risk_tier, threat_score,
            json.dumps(indicators), json.dumps(top_features), is_quarantined
        ))
        scan_id = cursor.lastrowid

        quarantine_id = None
        if is_quarantined:
            reason = f"Identified as {risk_tier} with {round(spam_prob * 100, 1)}% spam probability"
            cursor.execute("""
                INSERT INTO quarantine (
                    scan_id, timestamp, sender, subject, body,
                    spam_probability, risk_tier, status, reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'QUARANTINED', ?)
            """, (
                scan_id, now, sender, subject, body, spam_prob, risk_tier, reason
            ))
            quarantine_id = cursor.lastrowid

            # Also maintain sync with data/quarantine/quarantine.csv
            from src.quarantine.store import quarantine_email
            quarantine_email(body, label)

        conn.commit()

        return {
            "id": scan_id,
            "quarantine_id": quarantine_id,
            "timestamp": now,
            "sender": sender,
            "subject": subject,
            "label": label,
            "spam_probability": spam_prob,
            "ham_probability": ham_prob,
            "risk_tier": risk_tier,
            "threat_score": threat_score,
            "indicators": indicators,
            "top_features": top_features,
            "is_quarantined": bool(is_quarantined)
        }


def get_quarantined_items(status: Optional[str] = None, search: Optional[str] = None) -> List[Dict[str, Any]]:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        query = "SELECT * FROM quarantine WHERE 1=1"
        params = []

        if status and status.upper() != "ALL":
            query += " AND status = ?"
            params.append(status.upper())

        if search:
            query += " AND (sender LIKE ? OR subject LIKE ? OR body LIKE ?)"
            term = f"%{search}%"
            params.extend([term, term, term])

        query += " ORDER BY id DESC"
        cursor.execute(query, params)
        rows = cursor.fetchall()
        return [dict(row) for row in rows]


def update_quarantine_status(item_id: int, new_status: str) -> bool:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE quarantine SET status = ? WHERE id = ?", (new_status.upper(), item_id))
        conn.commit()
        return cursor.rowcount > 0


def delete_quarantine_item(item_id: int) -> bool:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM quarantine WHERE id = ?", (item_id,))
        conn.commit()
        return cursor.rowcount > 0


def get_all_scans(limit: int = 50, offset: int = 0, label: Optional[str] = None, search: Optional[str] = None) -> Dict[str, Any]:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        query = "SELECT * FROM scans WHERE 1=1"
        count_query = "SELECT COUNT(*) FROM scans WHERE 1=1"
        params = []

        if label and label.lower() != "all":
            query += " AND label = ?"
            count_query += " AND label = ?"
            params.append(label.lower())

        if search:
            query += " AND (sender LIKE ? OR subject LIKE ? OR body LIKE ?)"
            count_query += " AND (sender LIKE ? OR subject LIKE ? OR body LIKE ?)"
            term = f"%{search}%"
            params.extend([term, term, term])

        cursor.execute(count_query, params)
        total = cursor.fetchone()[0]

        query += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        cursor.execute(query, params)
        rows = cursor.fetchall()

        items = []
        for r in rows:
            d = dict(r)
            try:
                d["indicators"] = json.loads(d.get("indicators") or "[]")
            except Exception:
                d["indicators"] = []
            try:
                d["top_features"] = json.loads(d.get("top_features") or "[]")
            except Exception:
                d["top_features"] = []
            items.append(d)

        return {"total": total, "items": items}


def get_analytics_summary() -> Dict[str, Any]:
    with get_db_connection() as conn:
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM scans")
        total_scans = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM scans WHERE label = 'spam'")
        spam_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM scans WHERE label = 'ham'")
        ham_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM quarantine WHERE status = 'QUARANTINED'")
        quarantined_active = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM quarantine WHERE status = 'RELEASED'")
        quarantined_released = cursor.fetchone()[0]

        cursor.execute("SELECT AVG(spam_probability) FROM scans WHERE label = 'spam'")
        avg_spam_prob_row = cursor.fetchone()[0]
        avg_spam_prob = round(avg_spam_prob_row * 100, 1) if avg_spam_prob_row is not None else 0.0

        # Risk tier counts
        cursor.execute("SELECT risk_tier, COUNT(*) FROM scans GROUP BY risk_tier")
        risk_breakdown = {row[0]: row[1] for row in cursor.fetchall()}

        # Recent 10 scans
        cursor.execute("SELECT id, timestamp, sender, subject, label, spam_probability, risk_tier FROM scans ORDER BY id DESC LIMIT 10")
        recent_scans = [dict(r) for r in cursor.fetchall()]

        detection_rate = round((spam_count / total_scans * 100), 1) if total_scans > 0 else 0.0

        return {
            "total_scans": total_scans,
            "spam_count": spam_count,
            "ham_count": ham_count,
            "quarantined_active": quarantined_active,
            "quarantined_released": quarantined_released,
            "avg_spam_confidence": avg_spam_prob,
            "detection_rate": detection_rate,
            "risk_breakdown": risk_breakdown,
            "recent_scans": recent_scans
        }


def get_rules() -> List[Dict[str, Any]]:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM rules ORDER BY id DESC")
        return [dict(r) for r in cursor.fetchall()]


def add_rule(rule_type: str, value: str, action: str) -> Dict[str, Any]:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        now = datetime.now().isoformat()
        cursor.execute(
            "INSERT INTO rules (rule_type, value, action, created_at) VALUES (?, ?, ?, ?)",
            (rule_type, value.strip().lower(), action, now)
        )
        conn.commit()
        return {"id": cursor.lastrowid, "rule_type": rule_type, "value": value, "action": action, "created_at": now}


def delete_rule(rule_id: int) -> bool:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM rules WHERE id = ?", (rule_id,))
        conn.commit()
        return cursor.rowcount > 0
