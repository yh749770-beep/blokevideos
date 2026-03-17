import os
import sqlite3
import base64
import hashlib
import time
import urllib.parse
from flask import Flask, request, session, redirect, url_for, render_template, abort

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET_KEY"]

DB_PATH = "app.db"
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

ALLOWED_EMAILS = {
    "yh749770@gmail.com"
}


def sign_bunny_hls_url(video_id: str, expires_in_seconds: int = 900) -> str:
    expires = int(time.time()) + expires_in_seconds

    playlist_path = f"/{video_id}/playlist.m3u8"
    token_path = f"/{video_id}/"

    params = {
        "token_path": token_path,
    }

    sorted_params = "&".join(f"{k}={params[k]}" for k in sorted(params))
    hashable = f"{BUNNY_CDN_TOKEN_KEY}{token_path}{expires}{sorted_params}"

    digest = hashlib.sha256(hashable.encode("utf-8")).digest()
    token = base64.b64encode(digest).decode("utf-8")
    token = token.replace("+", "-").replace("/", "_").replace("=", "")

    encoded_token_path = urllib.parse.quote(token_path, safe="")

    return (
        f"https://{BUNNY_CDN_HOST}"
        f"/bcdn_token={token}&expires={expires}&token_path={encoded_token_path}"
        f"{playlist_path}"
    )


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            email TEXT PRIMARY KEY,
            locked_ip TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()


def get_client_ip() -> str:
    forwarded_for = request.headers.get("X-Forwarded-For", "").strip()
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.remote_addr or "unknown"


def upsert_user(email: str):
    conn = db()
    conn.execute(
        "INSERT OR IGNORE INTO users(email, locked_ip) VALUES(?, NULL)",
        (email,)
    )
    conn.commit()
    conn.close()


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


@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "GET":
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
    if not email:
        return redirect(url_for("home"))

    current_ip = get_client_ip()
    if not lock_or_check_ip(email, current_ip):
        return "גישה חסומה: IP נעול", 403

    video = VIDEOS.get(lesson_key)
    if not video:
        abort(404)

    signed_url = sign_bunny_hls_url(video["video_id"])
    print("SIGNED URL:", signed_url)

    return render_template(
        "watch.html",
        video_url=signed_url,
        title=video["title"],
        all_videos=VIDEOS
    )


@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    return redirect(url_for("home"))


if __name__ == "__main__":
    app.run(debug=True)
