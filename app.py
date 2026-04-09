import os
import psycopg
import base64
import hashlib
import time
import urllib.parse
import secrets
from flask import Flask, request, session, redirect, url_for, render_template, abort

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET_KEY"]

DATABASE_URL = os.environ["DATABASE_URL"]

VIDEOS = {
    "lesson1": {
        "title": "מפגש 1 - איך למצוא סיומת סטטית בקלות, איך למצוא הזזות באופן כללי וצירי בפרט, מה זה משוואת התאמה. עבודת בית 1",
        "video_id": "d577050b-38f4-466b-a041-95341b01e10a",
    },
    "lesson2": {
        "title": "מפגש 2 - מה זה הנחת ומשוואת ויליוט, איך טמפ' משפיעה על מבנה מסויים ולא מסויים סטטית, סדפ לפתרון תרגילי ויליוט(מוטות) ובכלל. חלק 1 של עבודת בית 2",
        "video_id": "87404965-1776-4fed-a46a-46cfba5dc2e0",
    },
    "lesson3": {
        "title": "מפגש 3 - חלק 2 של עבודת בית 2",
        "video_id": "245edcf6-8713-4aac-ae1f-d8cf6225c6c2",
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
ADMIN_EMAIL = "yh749770@gmail.com"
ADMIN_PASSWORD = os.environ["ADMIN_PASSWORD"]


def is_admin_email(email) -> bool:
    return isinstance(email, str) and email.strip().lower() == ADMIN_EMAIL
    
ALLOWED_EMAILS = {e.strip().lower() for e in ALLOWED_EMAILS}

BUNNY_CDN_HOST = os.environ["BUNNY_CDN_HOST"]
BUNNY_CDN_TOKEN_KEY = os.environ["BUNNY_CDN_TOKEN_KEY"]

DEVICE_COOKIE_NAME = "device_token"
DEVICE_COOKIE_MAX_AGE = 60 * 60 * 24 * 365  # 1 year


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
    return psycopg.connect(DATABASE_URL)


def make_device_token() -> str:
    return secrets.token_urlsafe(32)


def hash_device_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def init_db():
    conn = db()
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                email TEXT PRIMARY KEY
            )
        """)
        conn.execute("""
            ALTER TABLE users
            ADD COLUMN IF NOT EXISTS locked_device_hash TEXT
        """)
        conn.commit()
    finally:
        conn.close()


init_db()


def upsert_user(email: str):
    conn = db()
    try:
        conn.execute(
            """
            INSERT INTO users(email, locked_device_hash)
            VALUES(%s, NULL)
            ON CONFLICT (email) DO NOTHING
            """,
            (email,)
        )
        conn.commit()
    finally:
        conn.close()


def lock_or_check_device(email: str, device_token: str | None):
    conn = db()
    try:
        row = conn.execute(
            "SELECT locked_device_hash FROM users WHERE email = %s",
            (email,)
        ).fetchone()

        if not row:
            return {
                "ok": False,
                "reason": "user_not_found",
                "device_token": None,
            }

        locked_device_hash = row[0]

        if locked_device_hash is None:
            token_to_store = device_token or make_device_token()
            conn.execute(
                "UPDATE users SET locked_device_hash = %s WHERE email = %s",
                (hash_device_token(token_to_store), email)
            )
            conn.commit()
            return {
                "ok": True,
                "reason": "new_device_locked",
                "device_token": token_to_store,
            }

        if not device_token:
            return {
                "ok": False,
                "reason": "missing_device_cookie",
                "device_token": None,
            }

        if hash_device_token(device_token) != locked_device_hash:
            return {
                "ok": False,
                "reason": "different_device",
                "device_token": None,
            }

        return {
            "ok": True,
            "reason": "known_device",
            "device_token": device_token,
        }
    finally:
        conn.close()


def reset_user_device(email: str):
    conn = db()
    try:
        conn.execute(
            "UPDATE users SET locked_device_hash = NULL WHERE email = %s",
            (email,)
        )
        conn.commit()
    finally:
        conn.close()


@app.route("/admin/reset-all-devices", methods=["POST"])
def admin_reset_all_devices():
    current = session.get("email")
    if not is_admin_email(current):
        return "Forbidden", 403

    conn = db()
    try:
        conn.execute("UPDATE users SET locked_device_hash = NULL")
        conn.commit()
    finally:
        conn.close()

    return redirect(url_for("admin_users"))


@app.route("/admin/users")
def admin_users():
    current = session.get("email")
    if not is_admin_email(current):
        return "Forbidden", 403    

    conn = db()
    try:
        raw_rows = conn.execute(
            "SELECT email, locked_device_hash FROM users ORDER BY email"
        ).fetchall()
    finally:
        conn.close()

    rows = [
        {
            "email": r[0],
            "has_device": bool(r[1]),
        }
        for r in raw_rows
    ]
    return render_template("admin_users.html", rows=rows)


@app.route("/admin/reset-device/<path:email>", methods=["POST"])
def admin_reset_device(email):
    current = session.get("email")
    if not is_admin_email(current):
        return "Forbidden", 403

    reset_user_device(email)
    return redirect(url_for("admin_users"))


@app.route("/health")
def health():
    return "ok"


@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "GET":
        return render_template("login.html")

    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
   
    if email not in ALLOWED_EMAILS:
        return "המייל הזה לא מורשה", 403
    
    if is_admin_email(email):
        if password != ADMIN_PASSWORD:
            return "סיסמת מנהל שגויה", 403
        
        session["email"] = email
        first_lesson_key = next(iter(VIDEOS))
        return redirect(url_for("watch", lesson_key=first_lesson_key))
    
    upsert_user(email)

    device_token = request.cookies.get(DEVICE_COOKIE_NAME)
    device_check = lock_or_check_device(email, device_token)

    if not device_check["ok"]:
        return "המייל הזה כבר משויך לדפדפן אחר", 403

    session["email"] = email

    first_lesson_key = next(iter(VIDEOS))
    response = redirect(url_for("watch", lesson_key=first_lesson_key))

    response.set_cookie(
        DEVICE_COOKIE_NAME,
        device_check["device_token"],
        max_age=DEVICE_COOKIE_MAX_AGE,
        httponly=True,
        secure=True,
        samesite="Lax",
    )

    return response


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
