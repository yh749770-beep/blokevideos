import os
import sqlite3
import base64
import hashlib
import time
import urllib.parse
from flask import Flask, request, session, redirect, url_for, render_template, abort

def normalize_bunny_host(host: str) -> str:
    host = host.strip()
    host = host.replace("https://", "").replace("http://", "")
    host = host.strip("/")
    return host


def bunny_token_b64(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8").replace("+", "-").replace("/", "_").replace("=", "")


def sign_bunny_hls_url(video_id: str, expires_in_seconds: int = 3600, user_ip: str = "") -> str:
    expires = int(time.time()) + expires_in_seconds
    host = normalize_bunny_host(BUNNY_CDN_HOST)

    playlist_path = f"/{video_id}/playlist.m3u8"
    token_path = f"/{video_id}/"

    params = {
        "token_path": token_path
    }

    # חשוב: בלי URL-encoding בתוך ה-hash
    sorted_params = "&".join(
        f"{key}={params[key]}"
        for key in sorted(params.keys())
        if key not in ("token", "expires")
    )

    signed_path = token_path

    hashable = f"{BUNNY_CDN_TOKEN_KEY}{signed_path}{expires}{user_ip}{sorted_params}"
    digest = hashlib.sha256(hashable.encode("utf-8")).digest()
    token = bunny_token_b64(digest)

    # עדיף path-based token עבור HLS
    query_string = urllib.parse.urlencode({
        "expires": expires,
        "token_path": token_path
    })

    return f"https://{host}/bcdn_token={token}&{query_string}{playlist_path}"


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
    try:
        conn.execute(
            "INSERT OR IGNORE INTO users(email, locked_ip) VALUES(?, NULL)",
            (email,)
        )
        conn.commit()
    finally:
        conn.close()


def lock_or_check_ip(email: str, current_ip: str) -> bool:
    conn = db()
    try:
        row = conn.execute(
            "SELECT locked_ip FROM users WHERE email = ?",
            (email,)
        ).fetchone()

        if not row:
            return False

        locked_ip = row["locked_ip"]

        if locked_ip is None:
            conn.execute(
                "UPDATE users SET locked_ip = ? WHERE email = ?",
                (current_ip, email)
            )
            conn.commit()
            return True

        return locked_ip == current_ip
    finally:
        conn.close()


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

    signed_url = sign_bunny_hls_url(
        video_id=video["video_id"],
        expires_in_seconds=3600
    )

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
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port, debug=False)
