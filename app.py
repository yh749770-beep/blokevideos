import os
import psycopg
import base64
import hashlib
import time
import urllib.parse
from flask import Flask, request, session, redirect, url_for, render_template, abort

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET_KEY"]

DATABASE_URL = os.environ["DATABASE_URL"]

VIDEOS = {
    "lesson1": {
        "title": "מפגש 1 - איך למצוא סיומת סטטית בקלות, איך למצוא הזזות באופן כללי וצירי בפרט, מה זה משוואת התאמה",
        "video_id": "d577050b-38f4-466b-a041-95341b01e10a",
    },

}

ALLOWED_EMAILS = {
    "yh749770@gmail.com",
    "yigalhu@post.bgu.ac.il",
    "noamco2301@gmail.com",
    "kotekshahaf@gmail.com",
    "noamati2003@gmail.com",
    "Dor62297@gmail.com",
    "noga.benzoor1@gmail.com",
    "yuvalsturm4@gmail.com",
    "tomer.leshem@gmail.com",
    "Ofek5314@gmail.com",
    "Nave.liron1@gmail.com",
    "Itamarl5577@gmail.com",
    
}
ALLOWED_EMAILS = {e.strip().lower() for e in ALLOWED_EMAILS}
BUNNY_CDN_HOST = os.environ["BUNNY_CDN_HOST"]
BUNNY_CDN_TOKEN_KEY = os.environ["BUNNY_CDN_TOKEN_KEY"]
@app.route("/admin/reset-all-ips", methods=["POST"])
def admin_reset_all_ips():
    current = session.get("email")
    if current != "yh749770@gmail.com":
        return "Forbidden", 403

    conn = db()
    try:
        conn.execute("UPDATE users SET locked_ip = NULL")
        conn.commit()
    finally:
        conn.close()

    return redirect(url_for("admin_users"))
def reset_user_ip(email: str):
    conn = db()
    try:
        conn.execute(
            "UPDATE users SET locked_ip = NULL WHERE email = ?",
            (email,)
        )
        conn.commit()
    finally:
        conn.close()
@app.route("/admin/users")
def admin_users():
    current = session.get("email")
    if current != "yh749770@gmail.com":
        return "Forbidden", 403

    conn = db()
    try:
        rows = conn.execute(
            "SELECT email, locked_ip FROM users ORDER BY email"
        ).fetchall()
    finally:
        conn.close()

    return render_template("admin_users.html", rows=rows)


@app.route("/admin/reset-ip/<path:email>", methods=["POST"])
def admin_reset_ip(email):
    current = session.get("email")
    if current != "yh749770@gmail.com":
        return "Forbidden", 403

    reset_user_ip(email)
    return redirect(url_for("admin_users"))


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

    sorted_params = "&".join(
        f"{key}={params[key]}"
        for key in sorted(params.keys())
        if key not in ("token", "expires")
    )

    signed_path = token_path

    hashable = f"{BUNNY_CDN_TOKEN_KEY}{signed_path}{expires}{user_ip}{sorted_params}"
    digest = hashlib.sha256(hashable.encode("utf-8")).digest()
    token = bunny_token_b64(digest)

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


@app.route("/health")
def health():
    return "ok"


@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "GET":
        return render_template("login.html")

    email = request.form.get("email", "").strip().lower()

    if email not in ALLOWED_EMAILS:
        return "המייל הזה לא מורשה", 403

    current_ip = get_client_ip()

    upsert_user(email)

    if not lock_or_check_ip(email, current_ip):
        return "המייל הזה כבר מחובר מכתובת IP אחרת", 403

    session["email"] = email
    first_lesson_key = next(iter(VIDEOS))
    return redirect(url_for("watch", lesson_key=first_lesson_key))


@app.route("/watch/<lesson_key>")
def watch(lesson_key):
    if "email" not in session:
        return redirect(url_for("home"))

    video = VIDEOS.get(lesson_key)
    if not video:
        abort(404)

    return render_template(
        "watch.html",
        title=video["title"],
        video_id=video["video_id"],
        all_videos=VIDEOS
    )


@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    return redirect(url_for("home"))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port, debug=False)
