import os
import secrets
import sqlite3
import time
import hashlib
import base64
import urllib.parse
import smtplib
import ssl
from email.message import EmailMessage
from flask import Flask, request, session, redirect, url_for, render_template, abort

app = Flask(__name__)

app.secret_key = os.environ["FLASK_SECRET_KEY"]

DB_PATH = "app.db"

BUNNY_LIBRARY_ID = "618406"
VIDEOS = {
    "intro": {
        "title": "מבוא",
        "video_id": "642da5d1-57b4-4787-8265-197fdf951487",
    },
    "lesson2": {
        "title": "שיעור 2",
        "video_id": "18bb5caf-12f7-443d-8d94-53a26b5e9c03",
    },
    "lesson3": {
        "title": "שיעור 3",
        "video_id": "055a7f5c-66f0-432a-ab4f-2a592ffc0a34",
    },
}

BUNNY_CDN_HOST = os.environ["BUNNY_CDN_HOST"]
BUNNY_CDN_TOKEN_KEY = os.environ["BUNNY_CDN_TOKEN_KEY"]

SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ["SMTP_USER"]
SMTP_PASS = os.environ["SMTP_PASS"]
MAIL_FROM = os.environ["MAIL_FROM"]

ALLOWED_EMAILS = {
    "yh749770@gmail.com"
}

OTP_TTL_SECONDS = 600

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            email TEXT PRIMARY KEY,
            locked_ip TEXT,
            verified INTEGER NOT NULL DEFAULT 0
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS otps (
            email TEXT PRIMARY KEY,
            code_hash TEXT NOT NULL,
            expires_at INTEGER NOT NULL
        )
    """)
    conn.commit()
    conn.close()


# ---------- Helpers ----------
def get_client_ip() -> str:
    # If behind reverse proxy, you may need X-Forwarded-For handling
    forwarded_for = request.headers.get("X-Forwarded-For", "").strip()
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.remote_addr or "unknown"


def hash_code(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def send_email_code(to_email: str, code: str) -> None:
    msg = EmailMessage()
    msg["Subject"] = "Your login code"
    msg["From"] = MAIL_FROM
    msg["To"] = to_email
    msg.set_content(f"Your login code is: {code}\nIt expires in 10 minutes.")

    context = ssl.create_default_context()

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as server:
        server.ehlo()
        server.starttls(context=context)
        server.ehlo()
        server.login(SMTP_USER, SMTP_PASS)
        server.send_message(msg)

def upsert_user(email: str):
    conn = db()
    conn.execute(
        "INSERT OR IGNORE INTO users(email, locked_ip, verified) VALUES(?, NULL, 0)",
        (email,)
    )
    conn.commit()
    conn.close()


def save_otp(email: str, code: str):
    expires_at = int(time.time()) + OTP_TTL_SECONDS
    conn = db()
    conn.execute(
        "INSERT OR REPLACE INTO otps(email, code_hash, expires_at) VALUES(?, ?, ?)",
        (email, hash_code(code), expires_at)
    )
    conn.commit()
    conn.close()


def verify_otp(email: str, code: str) -> bool:
    conn = db()
    row = conn.execute(
        "SELECT code_hash, expires_at FROM otps WHERE email = ?",
        (email,)
    ).fetchone()

    if not row:
        conn.close()
        return False

    now_ts = int(time.time())
    ok = (row["expires_at"] >= now_ts and row["code_hash"] == hash_code(code))

    if ok:
        conn.execute("DELETE FROM otps WHERE email = ?", (email,))
        conn.execute("UPDATE users SET verified = 1 WHERE email = ?", (email,))
        conn.commit()

    conn.close()
    return ok


def lock_or_check_ip(email: str, current_ip: str) -> bool:
    conn = db()
    row = conn.execute(
        "SELECT locked_ip FROM users WHERE email = ?",
        (email,)
    ).fetchone()

    if not row:
        conn.close()
        return False

    locked_ip = row["locked_ip"]

    if locked_ip is None:
        conn.execute(
            "UPDATE users SET locked_ip = ? WHERE email = ?",
            (current_ip, email)
        )
        conn.commit()
        conn.close()
        return True

    conn.close()
    return locked_ip == current_ip






    # ---------- Routes ----------
@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "GET":
        email = session.get("email")
        if email:
            return redirect(url_for("watch", lesson_key="intro"))
        return render_template("login.html")

    email = request.form.get("email", "").strip().lower()

    if email not in ALLOWED_EMAILS:
        return "המייל הזה לא מורשה", 403

    upsert_user(email)
    session["email"] = email
    return redirect(url_for("watch", lesson_key="intro"))







@app.route("/watch/<lesson_key>")
def watch(lesson_key):
    email = session.get("email")
    if not email: return redirect(url_for("home"))

    current_ip = get_client_ip()
    if not lock_or_check_ip(email, current_ip):
        return "גישה חסומה: IP נעול", 403

    video = VIDEOS.get(lesson_key)
    if not video: abort(404)

    signed_url = sign_bunny_hls_url(video["video_id"])
    print("SIGNED URL:", signed_url)
    # הוספנו את VIDEOS כדי שהדף יוכל להציג את רשימת השיעורים
    return render_template("watch.html",
                           video_url=signed_url,
                           title=video["title"],
                           all_videos=VIDEOS) # שים לב לשורה הזו
@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    return redirect(url_for("home"))


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
