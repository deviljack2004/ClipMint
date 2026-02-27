from __future__ import annotations

import concurrent.futures
import json
import math
import os
import re
import secrets
import shutil
import smtplib
import sqlite3
import subprocess
import threading
import uuid
import hashlib
from datetime import datetime, timedelta
from email.message import EmailMessage
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from video_merging_tool import install_merge_tool

try:
    import psycopg
    from psycopg.rows import dict_row
except Exception:  # noqa: BLE001
    psycopg = None
    dict_row = None

try:
    from dotenv import load_dotenv
except Exception:  # noqa: BLE001
    load_dotenv = None

BASE_DIR = Path(__file__).resolve().parent
if load_dotenv is not None:
    load_dotenv(BASE_DIR / ".env")

UPLOAD_DIR = BASE_DIR / "uploads"
CLIPS_DIR = BASE_DIR / "clips"
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"
DOWNLOADS_DIR = BASE_DIR / "downloads"
MEMORY_FILE = BASE_DIR / "memory_store.json"
DOWNLOAD_MEMORY_FILE = BASE_DIR / "download_memory_store.json"
AUTH_DB_FILE = BASE_DIR / "auth.db"
AVATARS_DIR = STATIC_DIR / "avatars"
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
USE_POSTGRES_DB = bool(DATABASE_URL)
AUTH_DB_CONNECT_TIMEOUT = int(os.getenv("AUTH_DB_CONNECT_TIMEOUT", "5"))
AUTH_DB_BACKEND = "postgres" if USE_POSTGRES_DB else "sqlite"
DEFAULT_FFMPEG_EXE = Path(
    r"C:\Users\ANIRBAN SINHA\AppData\Local\Microsoft\WinGet\Packages\Gyan.FFmpeg_Microsoft.Winget.Source_8wekyb3d8bbwe\ffmpeg-8.0.1-full_build\bin\ffmpeg.exe"
)
DEFAULT_FFPROBE_EXE = DEFAULT_FFMPEG_EXE.with_name("ffprobe.exe")

DEFAULT_SEGMENT_SECONDS = 120
OUTPUT_WIDTH = 1080
OUTPUT_HEIGHT = 1920
WATERMARK_TEXT = "MOVIES CLIP CHAMP"
MAX_MEMORY_SOURCES = 2
DEFAULT_PROCESSING_MODE = "balanced"
PROCESSING_MODES = {"all_parallel", "balanced"}
DEFAULT_TEXT_PRIMARY = "MOVIES CLIP CHAMP"
DEFAULT_TEXT_SECONDARY = ""
DEFAULT_FONT_KEY = "arial"
DEFAULT_FONT_COLOR = "#FFFFFF"
DEFAULT_FONT_SIZE = 56
DEFAULT_TEXT_POSITION = "bottom_center"
DEFAULT_PART_POSITION = "top_right"
DEFAULT_USE_CUSTOM_TEXT = True
WATERMARK_FONT_SIZE = 60
ALLOWED_POSITIONS = {
    "top_left",
    "top_center",
    "top_right",
    "bottom_left",
    "bottom_center",
    "bottom_right",
}
FONT_FILES = {
    "arial": "Arial",
    "tahoma": "Tahoma",
    "verdana": "Verdana",
    "times": "Times New Roman",
    "impact": "Impact",
}

# Ensure required directories exist at startup.
for directory in (UPLOAD_DIR, CLIPS_DIR, STATIC_DIR, DOWNLOADS_DIR):
    directory.mkdir(parents=True, exist_ok=True)
AVATARS_DIR.mkdir(parents=True, exist_ok=True)

if not MEMORY_FILE.exists():
    MEMORY_FILE.write_text(json.dumps({"sources": []}, indent=2), encoding="utf-8")
if not DOWNLOAD_MEMORY_FILE.exists():
    DOWNLOAD_MEMORY_FILE.write_text(json.dumps({"items": []}, indent=2), encoding="utf-8")

app = FastAPI(title="AI Video Shorts Generator")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# Expose clips and static folders.
app.mount("/clips", StaticFiles(directory=str(CLIPS_DIR)), name="clips")
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
install_merge_tool(app)

JOBS: dict[str, dict] = {}
JOBS_LOCK = threading.Lock()
MEMORY_LOCK = threading.Lock()
DOWNLOAD_MEMORY_LOCK = threading.Lock()
ENCODER_CACHE: str | None = None
ENCODER_LOCK = threading.Lock()
BINARIES_LOCK = threading.Lock()
BINARIES_CACHE: dict[str, str] | None = None
DOWNLOAD_JOBS: dict[str, dict] = {}
DOWNLOAD_JOBS_LOCK = threading.Lock()
AUTH_LOCK = threading.Lock()
ALLOWED_DOWNLOAD_SOURCES = {"youtube", "instagram", "facebook", "x", "tiktok", "other"}
ALLOWED_DOWNLOAD_FORMATS = {"mp3", "mp4"}
ALLOWED_DOWNLOAD_PROFILES = {"ultra_fast", "fast", "balanced", "high_quality"}
MAX_DOWNLOAD_MEMORY_ITEMS = 5
OTP_TTL_MINUTES = 10
SESSION_TTL_DAYS = 7
SESSION_COOKIE_NAME = "clipmint_session"
OTP_ATTEMPT_LIMIT = 5
PASSWORD_MIN_LEN = 8
ADMIN_SESSION_COOKIE_NAME = "clipmint_admin_session"
ADMIN_SESSION_TTL_HOURS = int(os.getenv("ADMIN_SESSION_TTL_HOURS", "12"))
ADMIN_PANEL_USERNAME = (os.getenv("ADMIN_PANEL_USERNAME", "admin") or "admin").strip()
ADMIN_PANEL_PASSWORD = os.getenv("ADMIN_PANEL_PASSWORD", "").strip()
YT_DLP_PROGRESS_RE = re.compile(r"\[download\]\s+(\d+(?:\.\d+)?)%")
ARIA2_PROGRESS_RE = re.compile(r"\((\d{1,3}(?:\.\d+)?)%\)")
GENERIC_PROGRESS_RE = re.compile(r"(\d{1,3}(?:\.\d+)?)%")
TEMPLATE_PROGRESS_RE = re.compile(r"^download:\s*([0-9]+(?:\.[0-9]+)?)%")


class GenerateMorePayload(BaseModel):
    segment_seconds: int = DEFAULT_SEGMENT_SECONDS
    shorts_count: int = 10
    processing_mode: str = DEFAULT_PROCESSING_MODE
    use_custom_start: bool = False
    start_time_hhmmss: str | None = None
    end_time_hhmmss: str | None = None
    text_primary: str = DEFAULT_TEXT_PRIMARY
    text_secondary: str = DEFAULT_TEXT_SECONDARY
    font_key: str = DEFAULT_FONT_KEY
    font_color: str = DEFAULT_FONT_COLOR
    font_size: int = DEFAULT_FONT_SIZE
    text_position: str = DEFAULT_TEXT_POSITION
    part_position: str = DEFAULT_PART_POSITION
    use_custom_text: bool = DEFAULT_USE_CUSTOM_TEXT
    use_pixel_positioning: bool = False
    text1_x: int = 40
    text1_y: int = 1640
    text2_x: int = 40
    text2_y: int = 1710
    part_x: int = 820
    part_y: int = 40


def _utc_now() -> datetime:
    return datetime.utcnow()


def _db_iso_now() -> str:
    return _utc_now().isoformat(timespec="seconds") + "Z"


def _sql_params(query: str) -> str:
    if AUTH_DB_BACKEND == "postgres":
        return query.replace("?", "%s")
    return query


def _db_exec(conn, query: str, params: tuple = ()):
    return conn.execute(_sql_params(query), params)


def _auth_db_connection():
    global AUTH_DB_BACKEND
    if AUTH_DB_BACKEND == "postgres":
        if psycopg is None:
            print("[AUTH] psycopg not installed; falling back to sqlite auth DB.")
            AUTH_DB_BACKEND = "sqlite"
        else:
            try:
                return psycopg.connect(
                    DATABASE_URL,
                    row_factory=dict_row,
                    connect_timeout=AUTH_DB_CONNECT_TIMEOUT,
                )
            except Exception as exc:  # noqa: BLE001
                print(f"[AUTH] PostgreSQL unavailable ({exc}); falling back to sqlite auth DB.")
                AUTH_DB_BACKEND = "sqlite"
    conn = sqlite3.connect(str(AUTH_DB_FILE), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def _init_auth_db() -> None:
    with AUTH_LOCK:
        conn = _auth_db_connection()
        try:
            statements = [
                """
                CREATE TABLE IF NOT EXISTS users (
                  email TEXT PRIMARY KEY,
                  username TEXT NOT NULL,
                  password_hash TEXT NOT NULL DEFAULT '',
                  password_salt TEXT NOT NULL DEFAULT '',
                  account_status TEXT NOT NULL DEFAULT 'active',
                  avatar_url TEXT NOT NULL DEFAULT '',
                  theme TEXT NOT NULL DEFAULT 'dark',
                  created_at TEXT NOT NULL,
                  updated_at TEXT NOT NULL,
                  last_login_at TEXT NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS otp_codes (
                  email TEXT PRIMARY KEY,
                  code TEXT NOT NULL,
                  expires_at TEXT NOT NULL,
                  attempts INTEGER NOT NULL DEFAULT 0,
                  created_at TEXT NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS sessions (
                  token TEXT PRIMARY KEY,
                  email TEXT NOT NULL,
                  expires_at TEXT NOT NULL,
                  created_at TEXT NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS admin_sessions (
                  token TEXT PRIMARY KEY,
                  username TEXT NOT NULL,
                  expires_at TEXT NOT NULL,
                  created_at TEXT NOT NULL
                )
                """,
                "CREATE INDEX IF NOT EXISTS idx_sessions_email ON sessions(email)",
                "CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at)",
                "CREATE INDEX IF NOT EXISTS idx_otp_expires ON otp_codes(expires_at)",
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username)",
                "CREATE INDEX IF NOT EXISTS idx_admin_sessions_expires ON admin_sessions(expires_at)",
            ]
            for statement in statements:
                _db_exec(conn, statement)
            if AUTH_DB_BACKEND == "postgres":
                _db_exec(conn, "ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT NOT NULL DEFAULT ''")
                _db_exec(conn, "ALTER TABLE users ADD COLUMN IF NOT EXISTS password_salt TEXT NOT NULL DEFAULT ''")
                _db_exec(conn, "ALTER TABLE users ADD COLUMN IF NOT EXISTS account_status TEXT NOT NULL DEFAULT 'active'")
            else:
                cols = _db_exec(conn, "PRAGMA table_info(users)").fetchall()
                col_names = {str(row["name"]) for row in cols}
                if "password_hash" not in col_names:
                    _db_exec(conn, "ALTER TABLE users ADD COLUMN password_hash TEXT NOT NULL DEFAULT ''")
                if "password_salt" not in col_names:
                    _db_exec(conn, "ALTER TABLE users ADD COLUMN password_salt TEXT NOT NULL DEFAULT ''")
                if "account_status" not in col_names:
                    _db_exec(conn, "ALTER TABLE users ADD COLUMN account_status TEXT NOT NULL DEFAULT 'active'")
            conn.commit()
        finally:
            conn.close()


def _sanitize_email(email: str) -> str:
    return (email or "").strip().lower()


def _sanitize_username(username: str) -> str:
    return (username or "").strip()


def _password_hash(password: str, salt_hex: str) -> str:
    salt = bytes.fromhex(salt_hex)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return digest.hex()


def _new_password_salt() -> str:
    return secrets.token_hex(16)


def _verify_password(password: str, salt_hex: str, expected_hash: str) -> bool:
    if not salt_hex or not expected_hash:
        return False
    calc = _password_hash(password, salt_hex)
    return secrets.compare_digest(calc, expected_hash)


def _find_user_by_identifier(identifier: str) -> dict | None:
    token = (identifier or "").strip()
    if not token:
        return None
    lowered = token.lower()
    with AUTH_LOCK:
        conn = _auth_db_connection()
        try:
            row = _db_exec(
                conn,
                """
                SELECT email, username, avatar_url, theme, created_at, updated_at, last_login_at, password_hash, password_salt, account_status
                FROM users
                WHERE lower(email) = ? OR lower(username) = ?
                LIMIT 1
                """,
                (lowered, lowered),
            ).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()


def _get_user_by_email(email: str) -> dict | None:
    key = _sanitize_email(email)
    if not key:
        return None
    with AUTH_LOCK:
        conn = _auth_db_connection()
        try:
            row = _db_exec(
                conn,
                """
                SELECT email, username, avatar_url, theme, created_at, updated_at, last_login_at, password_hash, password_salt, account_status
                FROM users
                WHERE email = ?
                """,
                (key,),
            ).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()


def _upsert_user(email: str, username: str | None = None, avatar_url: str | None = None, theme: str | None = None) -> dict:
    key = _sanitize_email(email)
    if not key:
        raise HTTPException(status_code=400, detail="Invalid email.")
    now_iso = _db_iso_now()
    default_username = (username or key.split("@")[0] or "User").strip()[:40] or "User"
    safe_theme = theme if theme in {"dark", "light"} else "dark"

    with AUTH_LOCK:
        conn = _auth_db_connection()
        try:
            row = _db_exec(conn, "SELECT * FROM users WHERE email = ?", (key,)).fetchone()
            if row is None:
                _db_exec(
                    conn,
                    """
                    INSERT INTO users (email, username, password_hash, password_salt, account_status, avatar_url, theme, created_at, updated_at, last_login_at)
                    VALUES (?, ?, ?, ?, 'active', ?, ?, ?, ?, ?)
                    """,
                    (key, default_username, "", "", avatar_url or "", safe_theme, now_iso, now_iso, now_iso),
                )
            else:
                current = dict(row)
                new_username = (username.strip()[:40] if (username is not None and username.strip()) else current.get("username", default_username))
                new_avatar = (avatar_url.strip() if avatar_url is not None else str(current.get("avatar_url", "")))
                new_theme = safe_theme if theme in {"dark", "light"} else str(current.get("theme", "dark"))
                _db_exec(
                    conn,
                    """
                    UPDATE users
                    SET username = ?, avatar_url = ?, theme = ?, updated_at = ?, last_login_at = ?
                    WHERE email = ?
                    """,
                    (new_username, new_avatar, new_theme, now_iso, now_iso, key),
                )
            conn.commit()
        finally:
            conn.close()
    user = _get_user_by_email(key)
    if user is None:
        raise HTTPException(status_code=500, detail="Failed to persist user.")
    return user


def _create_user_with_password(email: str, username: str, password: str) -> dict:
    clean_email = _sanitize_email(email)
    clean_username = _sanitize_username(username)
    if not clean_email or not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", clean_email):
        raise HTTPException(status_code=400, detail="Enter a valid email address.")
    if not clean_username or len(clean_username) < 2:
        raise HTTPException(status_code=400, detail="Username must be at least 2 characters.")
    if len(password or "") < PASSWORD_MIN_LEN:
        raise HTTPException(status_code=400, detail=f"Password must be at least {PASSWORD_MIN_LEN} characters.")

    existing = _find_user_by_identifier(clean_email) or _find_user_by_identifier(clean_username)
    if existing is not None:
        raise HTTPException(status_code=409, detail="User already exists with this email or username.")

    now_iso = _db_iso_now()
    salt = _new_password_salt()
    password_hash = _password_hash(password, salt)
    with AUTH_LOCK:
        conn = _auth_db_connection()
        try:
            _db_exec(
                conn,
                """
                INSERT INTO users (email, username, password_hash, password_salt, account_status, avatar_url, theme, created_at, updated_at, last_login_at)
                VALUES (?, ?, ?, ?, 'active', '', 'dark', ?, ?, ?)
                """,
                (clean_email, clean_username, password_hash, salt, now_iso, now_iso, now_iso),
            )
            conn.commit()
        finally:
            conn.close()

    user = _get_user_by_email(clean_email)
    if user is None:
        raise HTTPException(status_code=500, detail="Failed to create user.")
    return user


def _cleanup_expired_otps() -> None:
    now_iso = _db_iso_now()
    with AUTH_LOCK:
        conn = _auth_db_connection()
        try:
            _db_exec(conn, "DELETE FROM otp_codes WHERE expires_at < ?", (now_iso,))
            conn.commit()
        finally:
            conn.close()


def _cleanup_expired_sessions() -> None:
    now_iso = _db_iso_now()
    with AUTH_LOCK:
        conn = _auth_db_connection()
        try:
            _db_exec(conn, "DELETE FROM sessions WHERE expires_at < ?", (now_iso,))
            conn.commit()
        finally:
            conn.close()


def _send_otp_email(email: str, otp_code: str) -> bool:
    host = os.getenv("SMTP_HOST", "").strip()
    port_raw = os.getenv("SMTP_PORT", "587").strip()
    user = os.getenv("SMTP_USER", "").strip()
    password = os.getenv("SMTP_PASSWORD", "").strip()
    sender = os.getenv("SMTP_FROM", user).strip()
    use_tls = os.getenv("SMTP_USE_TLS", "true").strip().lower() in {"1", "true", "yes", "on"}

    if not host or not sender:
        print(f"[AUTH] OTP for {email}: {otp_code}")
        return False

    try:
        port = int(port_raw or "587")
    except ValueError:
        port = 587

    msg = EmailMessage()
    msg["Subject"] = "ClipMint login verification code"
    msg["From"] = sender
    msg["To"] = email
    msg.set_content(
        f"Your ClipMint verification code is: {otp_code}\n\n"
        f"This code expires in {OTP_TTL_MINUTES} minutes."
    )

    with smtplib.SMTP(host, port, timeout=20) as smtp:
        if use_tls:
            smtp.starttls()
        if user and password:
            smtp.login(user, password)
        smtp.send_message(msg)
    return True


def _issue_session(email: str) -> str:
    token = secrets.token_urlsafe(32)
    expires_at_iso = (_utc_now() + timedelta(days=SESSION_TTL_DAYS)).isoformat(timespec="seconds") + "Z"
    now_iso = _db_iso_now()
    with AUTH_LOCK:
        conn = _auth_db_connection()
        try:
            _db_exec(
                conn,
                "INSERT INTO sessions (token, email, expires_at, created_at) VALUES (?, ?, ?, ?)",
                (token, _sanitize_email(email), expires_at_iso, now_iso),
            )
            conn.commit()
        finally:
            conn.close()
    return token


def _invalidate_session(token: str | None) -> None:
    if not token:
        return
    with AUTH_LOCK:
        conn = _auth_db_connection()
        try:
            _db_exec(conn, "DELETE FROM sessions WHERE token = ?", (token,))
            conn.commit()
        finally:
            conn.close()


def _current_user_from_request(request: Request) -> dict | None:
    _cleanup_expired_sessions()
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        return None
    with AUTH_LOCK:
        conn = _auth_db_connection()
        try:
            row = _db_exec(conn, "SELECT email FROM sessions WHERE token = ?", (token,)).fetchone()
        finally:
            conn.close()
    if row is None:
        return None
    email = _sanitize_email(str(row["email"]))
    user = _get_user_by_email(email)
    if user and str(user.get("account_status") or "active") != "active":
        _invalidate_session(token)
        return None
    return user


def _require_user(request: Request) -> dict:
    user = _current_user_from_request(request)
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication required.")
    return user


def _cleanup_expired_admin_sessions() -> None:
    now_iso = _db_iso_now()
    with AUTH_LOCK:
        conn = _auth_db_connection()
        try:
            _db_exec(conn, "DELETE FROM admin_sessions WHERE expires_at < ?", (now_iso,))
            conn.commit()
        finally:
            conn.close()


def _issue_admin_session(username: str) -> str:
    token = secrets.token_urlsafe(32)
    now_iso = _db_iso_now()
    expires_at_iso = (_utc_now() + timedelta(hours=ADMIN_SESSION_TTL_HOURS)).isoformat(timespec="seconds") + "Z"
    with AUTH_LOCK:
        conn = _auth_db_connection()
        try:
            _db_exec(
                conn,
                "INSERT INTO admin_sessions (token, username, expires_at, created_at) VALUES (?, ?, ?, ?)",
                (token, username, expires_at_iso, now_iso),
            )
            conn.commit()
        finally:
            conn.close()
    return token


def _invalidate_admin_session(token: str | None) -> None:
    if not token:
        return
    with AUTH_LOCK:
        conn = _auth_db_connection()
        try:
            _db_exec(conn, "DELETE FROM admin_sessions WHERE token = ?", (token,))
            conn.commit()
        finally:
            conn.close()


def _current_admin_from_request(request: Request) -> dict | None:
    _cleanup_expired_admin_sessions()
    token = request.cookies.get(ADMIN_SESSION_COOKIE_NAME)
    if not token:
        return None
    with AUTH_LOCK:
        conn = _auth_db_connection()
        try:
            row = _db_exec(
                conn,
                "SELECT username, expires_at, created_at FROM admin_sessions WHERE token = ?",
                (token,),
            ).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()


def _require_admin(request: Request) -> dict:
    admin = _current_admin_from_request(request)
    if admin is None:
        raise HTTPException(status_code=403, detail="Admin access required.")
    return admin


def _set_user_account_status(email: str, status: str) -> None:
    clean_email = _sanitize_email(email)
    if status not in {"active", "paused"}:
        raise HTTPException(status_code=400, detail="Invalid status.")
    if not clean_email:
        raise HTTPException(status_code=400, detail="Invalid email.")
    with AUTH_LOCK:
        conn = _auth_db_connection()
        try:
            row = _db_exec(conn, "SELECT email FROM users WHERE email = ?", (clean_email,)).fetchone()
            if row is None:
                raise HTTPException(status_code=404, detail="User not found.")
            _db_exec(conn, "UPDATE users SET account_status = ?, updated_at = ? WHERE email = ?", (status, _db_iso_now(), clean_email))
            if status == "paused":
                _db_exec(conn, "DELETE FROM sessions WHERE email = ?", (clean_email,))
            conn.commit()
        finally:
            conn.close()


def _delete_user_account(email: str) -> None:
    clean_email = _sanitize_email(email)
    if not clean_email:
        raise HTTPException(status_code=400, detail="Invalid email.")
    with AUTH_LOCK:
        conn = _auth_db_connection()
        try:
            row = _db_exec(conn, "SELECT email FROM users WHERE email = ?", (clean_email,)).fetchone()
            if row is None:
                raise HTTPException(status_code=404, detail="User not found.")
            _db_exec(conn, "DELETE FROM sessions WHERE email = ?", (clean_email,))
            _db_exec(conn, "DELETE FROM otp_codes WHERE email = ?", (clean_email,))
            _db_exec(conn, "DELETE FROM users WHERE email = ?", (clean_email,))
            conn.commit()
        finally:
            conn.close()


def _admin_dashboard_data() -> dict:
    now_iso = _db_iso_now()
    with AUTH_LOCK:
        conn = _auth_db_connection()
        try:
            users_count = int(_db_exec(conn, "SELECT COUNT(*) AS c FROM users").fetchone()["c"])
            paused_users = int(_db_exec(conn, "SELECT COUNT(*) AS c FROM users WHERE account_status = 'paused'").fetchone()["c"])
            sessions_count = int(_db_exec(conn, "SELECT COUNT(*) AS c FROM sessions").fetchone()["c"])
            active_sessions = int(
                _db_exec(conn, "SELECT COUNT(*) AS c FROM sessions WHERE expires_at > ?", (now_iso,)).fetchone()["c"]
            )
            otp_pending = int(_db_exec(conn, "SELECT COUNT(*) AS c FROM otp_codes WHERE expires_at > ?", (now_iso,)).fetchone()["c"])

            recent_users = [
                dict(row)
                for row in _db_exec(
                    conn,
                    """
                    SELECT email, username, created_at, last_login_at, theme, password_hash, account_status
                    FROM users
                    ORDER BY created_at DESC
                    LIMIT 20
                    """,
                ).fetchall()
            ]
            recent_sessions = [
                dict(row)
                for row in _db_exec(
                    conn,
                    """
                    SELECT email, created_at, expires_at
                    FROM sessions
                    ORDER BY created_at DESC
                    LIMIT 20
                    """,
                ).fetchall()
            ]
            recent_otps = [
                dict(row)
                for row in _db_exec(
                    conn,
                    """
                    SELECT email, created_at, expires_at, attempts
                    FROM otp_codes
                    ORDER BY created_at DESC
                    LIMIT 20
                    """,
                ).fetchall()
            ]
            return {
                "metrics": {
                    "users_count": users_count,
                    "paused_users": paused_users,
                    "sessions_count": sessions_count,
                    "active_sessions": active_sessions,
                    "otp_pending": otp_pending,
                },
                "recent_users": recent_users,
                "recent_sessions": recent_sessions,
                "recent_otps": recent_otps,
            }
        finally:
            conn.close()


_init_auth_db()


def _run_command(command: list[str]) -> subprocess.CompletedProcess:
    """Run a command and raise a clear runtime error if it fails."""
    if not command:
        raise RuntimeError("Empty command.")

    tool = command[0].lower()
    binaries = _resolve_binaries()
    if tool in binaries:
        command = [binaries[tool], *command[1:]]

    try:
        return subprocess.run(command, check=True, capture_output=True, text=True)
    except FileNotFoundError as exc:
        raise RuntimeError("FFmpeg/FFprobe not found. Ensure they are installed and in PATH.") from exc
    except subprocess.CalledProcessError as exc:
        stderr = (exc.stderr or "").strip()
        raise RuntimeError(stderr or "Command execution failed.") from exc


def _run_yt_dlp_command(command: list[str]) -> subprocess.CompletedProcess:
    """Run yt-dlp command and provide actionable errors."""
    yt_dlp_path = shutil.which("yt-dlp") or shutil.which("yt_dlp")
    if yt_dlp_path is None:
        raise RuntimeError("yt-dlp not found. Install yt-dlp and ensure it is available in PATH.")

    try:
        return subprocess.run([yt_dlp_path, *command], check=True, capture_output=True, text=True)
    except FileNotFoundError as exc:
        raise RuntimeError("yt-dlp not found. Install yt-dlp and ensure it is available in PATH.") from exc
    except subprocess.CalledProcessError as exc:
        merged = "\n".join(part for part in ((exc.stdout or "").strip(), (exc.stderr or "").strip()) if part).strip()
        tail = merged.splitlines()[-1] if merged else "Download failed."
        raise RuntimeError(tail) from exc


def _resolve_yt_dlp_executable() -> str:
    yt_dlp_path = shutil.which("yt-dlp") or shutil.which("yt_dlp")
    if yt_dlp_path is None:
        raise RuntimeError("yt-dlp not found. Install yt-dlp and ensure it is available in PATH.")
    return yt_dlp_path


def _resolve_binaries() -> dict[str, str]:
    """Resolve ffmpeg and ffprobe executable paths once and cache them."""
    global BINARIES_CACHE
    with BINARIES_LOCK:
        if BINARIES_CACHE is not None:
            return BINARIES_CACHE

        ffmpeg_path = None
        ffprobe_path = None

        # 1) Prefer known local WinGet install path provided by user.
        if DEFAULT_FFMPEG_EXE.exists():
            ffmpeg_path = str(DEFAULT_FFMPEG_EXE)
        if DEFAULT_FFPROBE_EXE.exists():
            ffprobe_path = str(DEFAULT_FFPROBE_EXE)

        # 2) Fallback to PATH lookup.
        if ffmpeg_path is None:
            ffmpeg_found = shutil.which("ffmpeg")
            if ffmpeg_found:
                ffmpeg_path = ffmpeg_found
        if ffprobe_path is None:
            ffprobe_found = shutil.which("ffprobe")
            if ffprobe_found:
                ffprobe_path = ffprobe_found

        if ffmpeg_path is None or ffprobe_path is None:
            raise RuntimeError("FFmpeg/FFprobe not found. Ensure they are installed and in PATH.")

        BINARIES_CACHE = {"ffmpeg": ffmpeg_path, "ffprobe": ffprobe_path}
        return BINARIES_CACHE


def _extract_downloaded_path(tool_output: str) -> Path | None:
    for raw in reversed(tool_output.splitlines()):
        candidate = raw.strip().strip('"')
        if not candidate:
            continue
        if candidate.lower().startswith("destination:"):
            candidate = candidate.split(":", 1)[1].strip().strip('"')
        path = Path(candidate)
        if path.exists() and path.is_file():
            return path
    return None


def _validate_download_inputs(url: str, source: str, output_format: str) -> tuple[str, str, str]:
    clean_url = (url or "").strip()
    if not clean_url:
        raise HTTPException(status_code=400, detail="Please paste a valid link.")
    if not re.match(r"^https?://", clean_url, flags=re.IGNORECASE):
        raise HTTPException(status_code=400, detail="Link must start with http:// or https://")

    source_key = (source or "other").strip().lower()
    if source_key not in ALLOWED_DOWNLOAD_SOURCES:
        raise HTTPException(status_code=400, detail="Unsupported source.")

    format_key = (output_format or "mp4").strip().lower()
    if format_key not in ALLOWED_DOWNLOAD_FORMATS:
        raise HTTPException(status_code=400, detail="Unsupported output format. Choose MP3 or MP4.")

    return clean_url, source_key, format_key


def _validate_download_profile(download_profile: str) -> str:
    profile = (download_profile or "balanced").strip().lower()
    if profile not in ALLOWED_DOWNLOAD_PROFILES:
        raise HTTPException(status_code=400, detail="Unsupported download profile.")
    return profile


def _read_download_memory() -> dict:
    with DOWNLOAD_MEMORY_LOCK:
        try:
            return json.loads(DOWNLOAD_MEMORY_FILE.read_text(encoding="utf-8"))
        except Exception:
            return {"items": []}


def _write_download_memory(data: dict) -> None:
    with DOWNLOAD_MEMORY_LOCK:
        DOWNLOAD_MEMORY_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _serialize_download_memory_items() -> list[dict]:
    memory = _read_download_memory()
    raw_items = memory.get("items", []) or []
    items = [item for item in raw_items if Path(str(item.get("file_path", ""))).exists()]
    if len(items) != len(raw_items):
        memory["items"] = items
        _write_download_memory(memory)
    output: list[dict] = []
    for item in items:
        item_id = str(item.get("id", ""))
        if not item_id:
            continue
        output.append(
            {
                "id": item_id,
                "file_name": item.get("file_name"),
                "output_format": item.get("output_format"),
                "source": item.get("source"),
                "created_at": item.get("created_at"),
                "size_bytes": int(item.get("size_bytes", 0) or 0),
                "preview_url": f"/api/downloader/memory/preview/{item_id}",
                "file_url": f"/api/downloader/memory/file/{item_id}",
            }
        )
    return output


def _find_download_memory_item_by_job_id(job_id: str) -> dict | None:
    memory = _read_download_memory()
    for item in memory.get("items", []) or []:
        if str(item.get("job_id", "")) == job_id:
            file_path = Path(str(item.get("file_path", "")))
            if file_path.exists():
                return item
    return None


def _extract_path_from_log_line(raw_line: str) -> Path | None:
    line = (raw_line or "").strip()
    if not line:
        return None

    patterns = [
        r"^\[download\]\s+Destination:\s+(.+)$",
        r"^\[ExtractAudio\]\s+Destination:\s+(.+)$",
        r"^\[Merger\]\s+Merging formats into\s+(.+)$",
    ]
    for pattern in patterns:
        match = re.match(pattern, line)
        if match:
            candidate = match.group(1).strip().strip('"')
            if candidate:
                return Path(candidate)

    if line.lower().startswith("destination:"):
        return Path(line.split(":", 1)[1].strip().strip('"'))

    # --print after_move:filepath may output plain absolute/relative path.
    if re.search(r"\.(mp4|m4a|webm|mp3|aac|wav|ogg)$", line, flags=re.IGNORECASE):
        return Path(line.strip('"'))
    return None


def _serialize_download_job(job: dict) -> dict:
    payload = {
        "job_id": job["job_id"],
        "status": job.get("status", "queued"),
        "progress": float(job.get("progress", 0.0)),
        "stage": job.get("stage", "starting"),
        "last_log": job.get("last_log"),
        "error": job.get("error"),
        "output_format": job.get("output_format"),
        "download_profile": job.get("download_profile", "balanced"),
        "file_name": job.get("file_name"),
        "created_at": job.get("created_at"),
        "started_at": job.get("started_at"),
        "completed_at": job.get("completed_at"),
    }
    if job.get("status") == "completed":
        payload["file_url"] = f"/api/downloader/file/{job['job_id']}"
        payload["preview_url"] = f"/api/downloader/preview/{job['job_id']}"
    return payload


def _set_download_job_failed(job_id: str, error_text: str) -> None:
    with DOWNLOAD_JOBS_LOCK:
        job = DOWNLOAD_JOBS.get(job_id)
        if job is None:
            return
        job["status"] = "failed"
        job["error"] = error_text or "Download failed."
        job["stage"] = "failed"
        job["last_log"] = (error_text or "Download failed.")[:300]
        job["process"] = None


def _set_download_job_cancelled(job_id: str) -> None:
    with DOWNLOAD_JOBS_LOCK:
        job = DOWNLOAD_JOBS.get(job_id)
        if job is None:
            return
        job["status"] = "cancelled"
        job["error"] = None
        job["progress"] = 0.0
        job["stage"] = "cancelled"
        job["last_log"] = "Download cancelled by user."
        job["process"] = None


def _terminate_download_process_tree(process: subprocess.Popen | None) -> None:
    if process is None:
        return
    if process.poll() is not None:
        return
    try:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                capture_output=True,
                text=True,
                check=False,
            )
        else:
            process.terminate()
    except Exception:
        pass


def _downloader_stage_from_line(line: str) -> str:
    low = line.lower()
    if "[extractaudio]" in low:
        return "extracting_audio"
    if "[merger]" in low:
        return "merging"
    if "[download]" in low or low.startswith("download:"):
        return "downloading"
    if "destination:" in low:
        return "preparing_output"
    return "processing"


def _next_download_filename(source_key: str, ext: str) -> str:
    source_label = re.sub(r"[^A-Za-z0-9]+", "", (source_key or "other")).upper() or "OTHER"
    date_label = datetime.now().strftime("%d.%m.%Y")
    prefix = f"{source_label}-{date_label}-"
    safe_ext = re.sub(r"[^A-Za-z0-9]+", "", (ext or "bin")).lower() or "bin"

    memory = _read_download_memory()
    used_numbers: set[int] = set()
    for item in memory.get("items", []) or []:
        name = str(item.get("file_name", ""))
        if not name.startswith(prefix):
            continue
        match = re.match(rf"^{re.escape(prefix)}(\d+)\.[A-Za-z0-9]+$", name)
        if match:
            try:
                used_numbers.add(int(match.group(1)))
            except ValueError:
                continue

    seq = 1
    while seq in used_numbers:
        seq += 1

    candidate = f"{prefix}{seq:02d}.{safe_ext}"
    while (DOWNLOADS_DIR / candidate).exists():
        seq += 1
        candidate = f"{prefix}{seq:02d}.{safe_ext}"
    return candidate


def _run_downloader_job(job_id: str, clean_url: str, format_key: str) -> None:
    try:
        yt_dlp_bin = _resolve_yt_dlp_executable()
    except RuntimeError as exc:
        _set_download_job_failed(job_id, str(exc))
        return

    with DOWNLOAD_JOBS_LOCK:
        job = DOWNLOAD_JOBS.get(job_id)
        if job is None:
            return
        request_id = str(job["request_id"])
        source_key = str(job.get("source", "other"))
        profile = str(job.get("download_profile", "balanced"))
        job["status"] = "processing"
        job["progress"] = 1.0
        job["error"] = None
        job["stage"] = "starting"
        job["last_log"] = "Starting downloader..."
        job["started_at"] = datetime.utcnow().isoformat(timespec="seconds") + "Z"

    output_template = str(DOWNLOADS_DIR / f"{request_id}.%(ext)s")
    concurrent_fragments = "8"
    mp3_quality = "2"
    format_selector = "b[ext=mp4]/bv*[ext=mp4]+ba[ext=m4a]/bv*+ba/b"
    if profile == "ultra_fast":
        concurrent_fragments = "20"
        mp3_quality = "7"
        format_selector = "worst[ext=mp4]/worst[vcodec!=none]/worst"
    elif profile == "fast":
        concurrent_fragments = "16"
        mp3_quality = "5"
        format_selector = "b[ext=mp4]/bv*[ext=mp4]+ba[ext=m4a]/b"
    elif profile == "high_quality":
        concurrent_fragments = "6"
        mp3_quality = "0"
        format_selector = "bv*+ba/b"

    common_args = [
        "--newline",
        "--no-playlist",
        "--restrict-filenames",
        "--prefer-free-formats",
        "--concurrent-fragments",
        concurrent_fragments,
        "--retries",
        "3",
        "--fragment-retries",
        "3",
        "--progress-template",
        "download:%(progress._percent_str)s|%(progress.status)s|%(progress.eta)s|%(progress.speed)s",
        "--print",
        "after_move:filepath",
        "-o",
        output_template,
        clean_url,
    ]

    if format_key == "mp3":
        cmd = ["-x", "--audio-format", "mp3", "--audio-quality", mp3_quality, *common_args]
        media_type = "audio/mpeg"
    else:
        cmd = ["-f", format_selector, "--merge-output-format", "mp4", *common_args]
        media_type = "video/mp4"

    log_tail: list[str] = []
    candidate_path: Path | None = None

    try:
        process = subprocess.Popen(
            [yt_dlp_bin, *cmd],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
    except Exception as exc:  # noqa: BLE001
        _set_download_job_failed(job_id, str(exc))
        return

    with DOWNLOAD_JOBS_LOCK:
        job = DOWNLOAD_JOBS.get(job_id)
        if job is not None:
            job["process"] = process

    if process.stdout is not None:
        for raw in process.stdout:
            with DOWNLOAD_JOBS_LOCK:
                active_job = DOWNLOAD_JOBS.get(job_id)
                if active_job is None:
                    break
                if bool(active_job.get("cancel_requested")):
                    _terminate_download_process_tree(process)
                    continue

            line = raw.strip()
            if line:
                log_tail.append(line)
                if len(log_tail) > 160:
                    log_tail.pop(0)
                with DOWNLOAD_JOBS_LOCK:
                    live = DOWNLOAD_JOBS.get(job_id)
                    if live is not None:
                        live["stage"] = _downloader_stage_from_line(line)
                        live["last_log"] = line[:300]

            pct_match = TEMPLATE_PROGRESS_RE.search(line)
            if pct_match is None:
                pct_match = YT_DLP_PROGRESS_RE.search(line)
            if pct_match is None:
                pct_match = ARIA2_PROGRESS_RE.search(line)
            if pct_match is None and ("eta" in line.lower() or "dl:" in line.lower() or "[download]" in line.lower()):
                pct_match = GENERIC_PROGRESS_RE.search(line)

            if pct_match:
                try:
                    pct = float(pct_match.group(1))
                except (TypeError, ValueError):
                    pct = 0.0
                with DOWNLOAD_JOBS_LOCK:
                    job = DOWNLOAD_JOBS.get(job_id)
                    if job is not None:
                        job["progress"] = max(float(job.get("progress", 0.0)), min(99.0, max(1.0, pct)))

            found = _extract_path_from_log_line(line)
            if found is not None:
                candidate_path = found

    return_code = process.wait()
    with DOWNLOAD_JOBS_LOCK:
        job = DOWNLOAD_JOBS.get(job_id)
        cancel_requested = bool(job.get("cancel_requested")) if job is not None else False

    if cancel_requested:
        _set_download_job_cancelled(job_id)
        return

    if return_code != 0:
        err_tail = log_tail[-1] if log_tail else "Download failed."
        _set_download_job_failed(job_id, err_tail)
        return

    output_path = None
    if candidate_path is not None and candidate_path.exists() and candidate_path.is_file():
        output_path = candidate_path
    else:
        matches = sorted(DOWNLOADS_DIR.glob(f"{request_id}.*"), key=lambda p: p.stat().st_mtime, reverse=True)
        if matches:
            output_path = matches[0]

    if output_path is None or not output_path.exists():
        _set_download_job_failed(job_id, "Download finished but output file was not found.")
        return

    desired_name = _next_download_filename(source_key, output_path.suffix.lstrip("."))
    desired_path = DOWNLOADS_DIR / desired_name
    try:
        if output_path.resolve() != desired_path.resolve():
            output_path.replace(desired_path)
            output_path = desired_path
    except Exception:
        # Keep original name on rename failure.
        pass

    with DOWNLOAD_JOBS_LOCK:
        job = DOWNLOAD_JOBS.get(job_id)
        if job is None:
            return
        job["status"] = "completed"
        job["progress"] = 100.0
        job["stage"] = "completed"
        job["last_log"] = "Download completed."
        job["file_path"] = str(output_path)
        job["file_name"] = output_path.name
        job["media_type"] = media_type
        job["process"] = None
        job["completed_at"] = datetime.utcnow().isoformat(timespec="seconds") + "Z"

    memory = _read_download_memory()
    items = list(memory.get("items", []) or [])
    items = [item for item in items if str(item.get("id", "")) and Path(str(item.get("file_path", ""))).exists()]
    if len(items) >= MAX_DOWNLOAD_MEMORY_ITEMS:
        # Safety guard for concurrent completions beyond capacity.
        oldest = items.pop(0)
        try:
            Path(str(oldest.get("file_path", ""))).unlink(missing_ok=True)
        except OSError:
            pass
    try:
        size_bytes = int(output_path.stat().st_size)
    except OSError:
        size_bytes = 0
    items.append(
        {
            "id": uuid.uuid4().hex,
            "job_id": job_id,
            "file_name": output_path.name,
            "file_path": str(output_path),
            "output_format": format_key,
            "media_type": media_type,
            "source": source_key,
            "url": clean_url,
            "size_bytes": size_bytes,
            "created_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        }
    )
    memory["items"] = items[-MAX_DOWNLOAD_MEMORY_ITEMS:]
    _write_download_memory(memory)


def _read_memory() -> dict:
    with MEMORY_LOCK:
        try:
            return json.loads(MEMORY_FILE.read_text(encoding="utf-8"))
        except Exception:
            return {"sources": []}


def _write_memory(data: dict) -> None:
    with MEMORY_LOCK:
        MEMORY_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _get_video_duration_seconds(input_path: Path) -> float:
    """Get source video duration via ffprobe."""
    probe_cmd = [
        "ffprobe",
        "-v",
        "error",
        "-show_entries",
        "format=duration",
        "-of",
        "json",
        str(input_path),
    ]
    result = _run_command(probe_cmd)
    data = json.loads(result.stdout)

    duration = float(data.get("format", {}).get("duration", 0.0))
    if duration <= 0:
        raise RuntimeError("Unable to read a valid video duration.")
    return duration


def _build_filter_complex_base() -> str:
    """Create 9:16 pipeline with solid black background and centered foreground."""
    return (
        f"[0:v]scale={OUTPUT_WIDTH}:{OUTPUT_HEIGHT}:flags=fast_bilinear:force_original_aspect_ratio=decrease,"
        f"pad={OUTPUT_WIDTH}:{OUTPUT_HEIGHT}:(ow-iw)/2:(oh-ih)/2:color=black[vbase]"
    )


def _format_seconds_to_hhmmss(seconds: int) -> str:
    """Format integer seconds as HH:MM:SS."""
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    secs = seconds % 60
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


def _font_name_for_key(font_key: str) -> str:
    return FONT_FILES.get(font_key, FONT_FILES[DEFAULT_FONT_KEY])


def _escape_drawtext_text(text: str) -> str:
    """Escape drawtext-sensitive chars."""
    escaped = text.replace("\\", "\\\\")
    escaped = escaped.replace(":", r"\:")
    escaped = escaped.replace("'", r"\'")
    escaped = escaped.replace("%", r"\%")
    return escaped


def _validate_overlay_options(
    use_custom_text: bool,
    text_primary: str,
    text_secondary: str,
    font_key: str,
    font_color: str,
    font_size: int,
    text_position: str,
    part_position: str,
    use_pixel_positioning: bool,
    text1_x: int,
    text1_y: int,
    text2_x: int,
    text2_y: int,
    part_x: int,
    part_y: int,
) -> dict:
    primary = (text_primary or "").strip()[:120]
    secondary = (text_secondary or "").strip()[:120]
    if not primary:
        primary = DEFAULT_TEXT_PRIMARY

    key = (font_key or DEFAULT_FONT_KEY).strip().lower()
    if key not in FONT_FILES:
        key = DEFAULT_FONT_KEY

    color = (font_color or DEFAULT_FONT_COLOR).strip()
    if not re.fullmatch(r"#[0-9A-Fa-f]{6}", color):
        color = DEFAULT_FONT_COLOR

    try:
        size = int(font_size)
    except (TypeError, ValueError):
        size = DEFAULT_FONT_SIZE
    size = max(20, min(120, size))

    meta_pos = (text_position or DEFAULT_TEXT_POSITION).strip().lower()
    part_pos = (part_position or DEFAULT_PART_POSITION).strip().lower()
    if meta_pos not in ALLOWED_POSITIONS:
        meta_pos = DEFAULT_TEXT_POSITION
    if part_pos not in ALLOWED_POSITIONS:
        part_pos = DEFAULT_PART_POSITION

    def clamp_x(v: int) -> int:
        return max(0, min(OUTPUT_WIDTH - 10, int(v)))

    def clamp_y(v: int) -> int:
        return max(0, min(OUTPUT_HEIGHT - 10, int(v)))

    return {
        "use_custom_text": bool(use_custom_text),
        "text_primary": primary,
        "text_secondary": secondary,
        "font_key": key,
        "font_color": color,
        "font_size": size,
        "text_position": meta_pos,
        "part_position": part_pos,
        "use_pixel_positioning": bool(use_pixel_positioning),
        "text1_x": clamp_x(text1_x),
        "text1_y": clamp_y(text1_y),
        "text2_x": clamp_x(text2_x),
        "text2_y": clamp_y(text2_y),
        "part_x": clamp_x(part_x),
        "part_y": clamp_y(part_y),
    }


def _xy_for_position(position: str, y_override: str | None = None) -> tuple[str, str]:
    if position == "top_left":
        return "40", y_override or "40"
    if position == "top_center":
        return "(w-text_w)/2", y_override or "40"
    if position == "top_right":
        return "w-text_w-40", y_override or "40"
    if position == "bottom_left":
        return "40", y_override or "h-text_h-40"
    if position == "bottom_center":
        return "(w-text_w)/2", y_override or "h-text_h-40"
    if position == "bottom_right":
        return "w-text_w-40", y_override or "h-text_h-40"
    return "(w-text_w)/2", y_override or "h-text_h-40"


def _drawtext_filter(
    in_label: str,
    out_label: str,
    text: str,
    font_color: str,
    font_size: int,
    x_expr: str,
    y_expr: str,
    font_name: str,
) -> str:
    return (
        f"[{in_label}]drawtext=text='{_escape_drawtext_text(text)}'"
        f":font='{_escape_drawtext_text(font_name)}':fontcolor={font_color}:fontsize={font_size}:x={x_expr}:y={y_expr}"
        f"[{out_label}]"
    )


def _build_filter_complex_with_overlay(overlay: dict, part_label: str) -> str:
    base = _build_filter_complex_base()
    font_name = _font_name_for_key(overlay["font_key"])
    font_color = overlay["font_color"]
    font_size = int(overlay["font_size"])
    # Position editor popup is the single source of truth for custom text positions.
    # Use direct validated pixel values to avoid drawtext expression parsing issues.
    x1 = str(int(overlay["text1_x"]))
    y1 = str(int(overlay["text1_y"]))
    x2 = str(int(overlay["text2_x"]))
    y2 = str(int(overlay["text2_y"]))
    p_x = str(int(overlay["part_x"]))
    p_y = str(int(overlay["part_y"]))

    primary = overlay["text_primary"]
    secondary = overlay["text_secondary"]
    use_custom_text = bool(overlay.get("use_custom_text", True))
    wm_x, wm_y = _xy_for_position("bottom_center", "h-text_h-40")

    # Permanent watermark is always rendered, regardless of custom text toggle.
    watermark_tail = _drawtext_filter("vwm_in", "vout", WATERMARK_TEXT, "white", WATERMARK_FONT_SIZE, wm_x, wm_y, font_name)

    if not use_custom_text:
        return f"{base};{watermark_tail.replace('[vwm_in]', '[vbase]', 1)}"

    if secondary:
        return (
            f"{base};"
            f"{_drawtext_filter('vbase', 'v1', primary, font_color, font_size, x1, y1, font_name)};"
            f"{_drawtext_filter('v1', 'v2', secondary, font_color, max(18, font_size - 8), x2, y2, font_name)};"
            f"{_drawtext_filter('v2', 'v3', part_label, font_color, max(20, font_size - 4), p_x, p_y, font_name)};"
            f"{watermark_tail.replace('[vwm_in]', '[v3]', 1)}"
        )
    return (
        f"{base};"
        f"{_drawtext_filter('vbase', 'v1', primary, font_color, font_size, x1, y1, font_name)};"
        f"{_drawtext_filter('v1', 'v2', part_label, font_color, max(20, font_size - 4), p_x, p_y, font_name)};"
        f"{watermark_tail.replace('[vwm_in]', '[v2]', 1)}"
    )


def _detect_best_video_encoder() -> str:
    """Prefer NVENC on supported machines; fallback to libx264."""
    global ENCODER_CACHE
    with ENCODER_LOCK:
        if ENCODER_CACHE is not None:
            return ENCODER_CACHE

        try:
            result = _run_command(["ffmpeg", "-hide_banner", "-encoders"])
            encoders_text = result.stdout.lower()
            ENCODER_CACHE = "h264_nvenc" if "h264_nvenc" in encoders_text else "libx264"
        except Exception:
            ENCODER_CACHE = "libx264"

        return ENCODER_CACHE


def _video_codec_args() -> list[str]:
    """Return encoder args tuned for speed."""
    encoder = _detect_best_video_encoder()
    if encoder == "h264_nvenc":
        return [
            "-c:v",
            "h264_nvenc",
            "-preset",
            "p4",
            "-rc",
            "vbr",
            "-cq",
            "24",
            "-b:v",
            "0",
            "-pix_fmt",
            "yuv420p",
        ]
    return [
        "-c:v",
        "libx264",
        "-preset",
        "veryfast",
        "-crf",
        "24",
        "-pix_fmt",
        "yuv420p",
        "-threads",
        "0",
    ]


def _software_codec_args() -> list[str]:
    """Guaranteed software encoder fallback args."""
    return [
        "-c:v",
        "libx264",
        "-preset",
        "veryfast",
        "-crf",
        "24",
        "-pix_fmt",
        "yuv420p",
        "-threads",
        "0",
    ]


def _recompute_progress(job: dict) -> None:
    clips = job.get("clips", [])
    if not clips:
        job["overall_progress"] = 0.0
        job["completed_segments"] = 0
        job["current_segment_index"] = None
        return

    total = 0.0
    completed = 0
    current_index: int | None = None

    for clip in clips:
        status = str(clip.get("status", "pending"))
        progress = float(clip.get("progress", 0.0))

        if status == "done":
            progress = 100.0
            completed += 1
        elif status == "finalizing":
            progress = 100.0
            if current_index is None:
                current_index = int(clip.get("index", 0))
        elif status == "cancelled":
            progress = 0.0
        else:
            progress = max(0.0, min(99.0, progress))
            if status == "processing" and current_index is None:
                current_index = int(clip.get("index", 0))

        clip["progress"] = round(progress, 2)
        total += progress

    job["completed_segments"] = completed
    job["current_segment_index"] = current_index
    job["overall_progress"] = round(total / len(clips), 2)


def _serialize_job(job: dict) -> dict:
    """Return API-safe job payload (without process handles)."""
    return {
        "job_id": job["job_id"],
        "status": job["status"],
        "error": job.get("error"),
        "source_id": job.get("source_id"),
        "segment_seconds": job.get("segment_seconds"),
        "requested_count": job.get("requested_count"),
        "processing_mode": job.get("processing_mode", DEFAULT_PROCESSING_MODE),
        "start_seconds": job.get("start_seconds", 0),
        "start_hhmmss": _format_seconds_to_hhmmss(int(job.get("start_seconds", 0) or 0)),
        "end_seconds": job.get("end_seconds"),
        "end_hhmmss": _format_seconds_to_hhmmss(int(job.get("end_seconds", 0) or 0)) if job.get("end_seconds") is not None else None,
        "overlay": job.get("overlay", {}),
        "source_duration": job.get("source_duration"),
        "source_duration_hhmmss": job.get("source_duration_hhmmss"),
        "total_segments": job.get("total_segments", 0),
        "completed_segments": job.get("completed_segments", 0),
        "overall_progress": job.get("overall_progress", 0.0),
        "current_segment_index": job.get("current_segment_index"),
        "cancel_requested": job.get("cancel_requested", False),
        "clips": job.get("clips", []),
    }


def _terminate_job_processes(job: dict) -> None:
    processes = list(job.get("current_processes", {}).values())
    for process in processes:
        if process is not None and process.poll() is None:
            process.terminate()


def _finalize_mp4_playable(path: Path) -> None:
    """Second phase to guarantee browser-playable mp4 with moov front."""
    tmp = path.with_suffix(".final.mp4")
    cmd = [
        "ffmpeg",
        "-y",
        "-i",
        str(path),
        "-c",
        "copy",
        "-movflags",
        "+faststart",
        str(tmp),
    ]
    _run_command(cmd)
    tmp.replace(path)


def _build_source_output_dir(source_id: str, segment_seconds: int) -> Path:
    output_dir = CLIPS_DIR / source_id / f"d{segment_seconds}"
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


def _render_segment(job_id: str, input_path: Path, overlay: dict, output_dir: Path, clip_pos: int) -> str:
    """Render a single segment with progress updates and finalization phase."""
    with JOBS_LOCK:
        job = JOBS[job_id]
        clip = job["clips"][clip_pos]
        if job.get("cancel_requested"):
            clip["status"] = "cancelled"
            clip["progress"] = 0.0
            _recompute_progress(job)
            return "cancelled"

        clip["status"] = "processing"
        clip["progress"] = 0.0
        _recompute_progress(job)
        clip_duration = max(1, int(clip.get("duration_sec", job["segment_seconds"])))

    start_time = int(job["clips"][clip_pos]["start_seconds"])
    output_name = f"short_{int(job['clips'][clip_pos]['index']):03d}.mp4"
    output_path = output_dir / output_name
    part_label = str(job["clips"][clip_pos].get("part_label", f"PART-{clip_pos + 1}"))
    filter_complex = _build_filter_complex_with_overlay(overlay, part_label)

    video_args = _video_codec_args()
    ffmpeg_cmd = [
        "ffmpeg",
        "-y",
        "-hwaccel",
        "auto",
        "-ss",
        str(start_time),
        "-i",
        str(input_path),
        "-t",
        str(job["segment_seconds"]),
        "-filter_complex",
        filter_complex,
        "-map",
        "[vout]",
        "-map",
        "0:a?",
        *video_args,
        "-c:a",
        "aac",
        "-b:a",
        "160k",
        "-r",
        "30",
        "-movflags",
        "+faststart",
        "-progress",
        "pipe:1",
        "-nostats",
        str(output_path),
    ]

    try:
        process = subprocess.Popen(
            ffmpeg_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("FFmpeg/FFprobe not found. Ensure they are installed and in PATH.") from exc

    with JOBS_LOCK:
        JOBS[job_id]["current_processes"][clip_pos] = process

    log_tail: list[str] = []

    try:
        if process.stdout is not None:
            for raw_line in process.stdout:
                line = raw_line.strip()
                if line:
                    log_tail.append(line)
                    if len(log_tail) > 120:
                        log_tail.pop(0)

                with JOBS_LOCK:
                    cancel_requested = JOBS[job_id].get("cancel_requested", False)

                if cancel_requested and process.poll() is None:
                    process.terminate()

                if line.startswith("out_time_ms="):
                    try:
                        out_time_ms = int(line.split("=", 1)[1])
                    except ValueError:
                        out_time_ms = 0

                    pct = min(99.0, (out_time_ms / (clip_duration * 1_000_000)) * 100.0)
                    with JOBS_LOCK:
                        job = JOBS[job_id]
                        clip = job["clips"][clip_pos]
                        if clip["status"] == "processing":
                            clip["progress"] = round(pct, 2)
                            _recompute_progress(job)

                elif line == "progress=end":
                    with JOBS_LOCK:
                        job = JOBS[job_id]
                        clip = job["clips"][clip_pos]
                        if clip["status"] == "processing":
                            clip["status"] = "finalizing"
                            clip["progress"] = 100.0
                            _recompute_progress(job)

        return_code = process.wait()

        with JOBS_LOCK:
            job = JOBS[job_id]
            job["current_processes"].pop(clip_pos, None)
            cancel_requested = job.get("cancel_requested", False)

        if cancel_requested:
            try:
                output_path.unlink(missing_ok=True)
            except OSError:
                pass
            with JOBS_LOCK:
                job = JOBS[job_id]
                clip = job["clips"][clip_pos]
                clip["status"] = "cancelled"
                clip["progress"] = 0.0
                _recompute_progress(job)
            return "cancelled"

        if return_code != 0:
            # Retry once in pure software mode when hardware path fails.
            used_nvenc = "h264_nvenc" in " ".join(video_args).lower()
            if used_nvenc:
                try:
                    output_path.unlink(missing_ok=True)
                except OSError:
                    pass

                retry_cmd = [
                    "ffmpeg",
                    "-y",
                    "-ss",
                    str(start_time),
                    "-i",
                    str(input_path),
                    "-t",
                    str(job["segment_seconds"]),
                    "-filter_complex",
                    filter_complex,
                    "-map",
                    "[vout]",
                    "-map",
                    "0:a?",
                    *_software_codec_args(),
                    "-c:a",
                    "aac",
                    "-b:a",
                    "160k",
                    "-r",
                    "30",
                    "-movflags",
                    "+faststart",
                    str(output_path),
                ]
                try:
                    _run_command(retry_cmd)
                    with JOBS_LOCK:
                        job = JOBS[job_id]
                        clip = job["clips"][clip_pos]
                        clip["status"] = "finalizing"
                        clip["progress"] = 100.0
                        _recompute_progress(job)
                except Exception as retry_exc:
                    tail = "\n".join(log_tail[-15:]).strip()
                    retry_msg = str(retry_exc).strip()
                    detail = retry_msg or tail or "Unknown FFmpeg error."
                    raise RuntimeError(f"FFmpeg failed while creating {output_name}. {detail}") from retry_exc
            else:
                tail = "\n".join(log_tail[-15:]).strip()
                detail = tail or "Unknown FFmpeg error."
                raise RuntimeError(f"FFmpeg failed while creating {output_name}. {detail}")

        with JOBS_LOCK:
            job = JOBS[job_id]
            clip = job["clips"][clip_pos]
            clip["status"] = "finalizing"
            clip["progress"] = 100.0
            _recompute_progress(job)

        _finalize_mp4_playable(output_path)

        # Validate finalized clip so frontend only shows truly playable files as done.
        _get_video_duration_seconds(output_path)

        with JOBS_LOCK:
            job = JOBS[job_id]
            clip = job["clips"][clip_pos]
            clip["status"] = "done"
            clip["progress"] = 100.0
            _recompute_progress(job)

        return "done"
    finally:
        with JOBS_LOCK:
            if job_id in JOBS:
                JOBS[job_id]["current_processes"].pop(clip_pos, None)


def _process_video_job(
    job_id: str,
    source: dict,
    segment_seconds: int,
    start_seconds: int,
    end_seconds: int,
    requested_count: int,
    use_custom_timeline: bool,
    overlay: dict,
) -> None:
    """Background worker that processes requested segments in parallel."""
    input_path = Path(source["file_path"])

    try:
        duration = float(source["duration_sec"])
        if start_seconds >= math.ceil(duration):
            raise RuntimeError("No remaining timeline to generate more shorts for this duration.")

        remaining_total_seconds = max(0, min(math.ceil(duration), end_seconds) - start_seconds)
        max_possible = max(1, math.ceil(remaining_total_seconds / segment_seconds))
        clip_count = min(requested_count, max_possible)
        if clip_count <= 0:
            raise RuntimeError("No remaining timeline to generate more shorts for this duration.")
        indices = list(range(clip_count))
        profile_key = str(segment_seconds)
        base_seq = int(source.get("profiles", {}).get(profile_key, 0))
        base_part = int(source.get("part_counter", 0))

        clips: list[dict[str, object]] = []
        for pos in indices:
            start_sec = start_seconds + (pos * segment_seconds)
            end_sec = min(start_sec + segment_seconds, math.ceil(duration))
            seq_no = base_seq + pos
            clip_name = f"short_{seq_no:03d}.mp4"
            clip_url = f"/clips/{source['id']}/d{segment_seconds}/{clip_name}"
            clips.append(
                {
                    "index": seq_no,
                    "name": clip_name,
                    "url": clip_url,
                    "part_label": f"PART-{base_part + pos + 1}",
                    "start": _format_seconds_to_hhmmss(start_sec),
                    "end": _format_seconds_to_hhmmss(end_sec),
                    "timeline": f"{_format_seconds_to_hhmmss(start_sec)} - {_format_seconds_to_hhmmss(end_sec)}",
                    "start_seconds": start_sec,
                    "duration_sec": end_sec - start_sec,
                    "status": "pending",
                    "progress": 0.0,
                }
            )

        with JOBS_LOCK:
            job = JOBS[job_id]
            job["status"] = "processing"
            job["source_duration"] = duration
            job["source_duration_hhmmss"] = _format_seconds_to_hhmmss(math.ceil(duration))
            job["total_segments"] = len(clips)
            job["clips"] = clips
            job["overall_progress"] = 0.0
            job["current_processes"] = {}
            _recompute_progress(job)

        output_dir = _build_source_output_dir(source["id"], segment_seconds)

        with JOBS_LOCK:
            mode = str(JOBS[job_id].get("processing_mode", DEFAULT_PROCESSING_MODE))

        if mode == "all_parallel":
            workers = len(indices)
        else:
            cpu = max(1, os.cpu_count() or 2)
            workers = max(1, min(len(indices), max(2, cpu // 2)))

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [
                executor.submit(_render_segment, job_id, input_path, overlay, output_dir, pos)
                for pos in range(len(indices))
            ]

            for future in concurrent.futures.as_completed(futures):
                with JOBS_LOCK:
                    if JOBS[job_id].get("cancel_requested"):
                        _terminate_job_processes(JOBS[job_id])
                try:
                    future.result()
                except Exception:
                    with JOBS_LOCK:
                        job = JOBS[job_id]
                        job["cancel_requested"] = True
                        _terminate_job_processes(job)
                    raise

        with JOBS_LOCK:
            job = JOBS[job_id]
            if job.get("cancel_requested"):
                for clip in job["clips"]:
                    if clip["status"] in {"pending", "processing", "finalizing"}:
                        clip["status"] = "cancelled"
                        clip["progress"] = 0.0
                _recompute_progress(job)
                job["status"] = "cancelled"
                return

            for clip in job["clips"]:
                clip_path = output_dir / str(clip["name"])
                if clip_path.exists() and clip["status"] != "done":
                    clip["status"] = "done"
                    clip["progress"] = 100.0
            _recompute_progress(job)
            job["overall_progress"] = 100.0
            job["status"] = "completed"
            job["current_segment_index"] = None

        # Persist global timeline cursor and per-duration sequence counter.
        memory = _read_memory()
        for src in memory.get("sources", []):
            if src.get("id") == source["id"]:
                profiles = src.setdefault("profiles", {})
                previous = int(profiles.get(profile_key, 0))
                profiles[profile_key] = max(previous, base_seq + len(clips))
                if not use_custom_timeline:
                    new_cursor = min(math.ceil(duration), start_seconds + (len(clips) * segment_seconds))
                    src["cursor_sec"] = max(int(src.get("cursor_sec", 0)), int(new_cursor))
                src["part_counter"] = max(int(src.get("part_counter", 0)), base_part + len(clips))
                break
        _write_memory(memory)

    except Exception as exc:  # noqa: BLE001
        with JOBS_LOCK:
            if job_id in JOBS:
                job = JOBS[job_id]
                job["status"] = "failed"
                job["error"] = str(exc)
                _recompute_progress(job)
                _terminate_job_processes(job)
    finally:
        with JOBS_LOCK:
            if job_id in JOBS:
                JOBS[job_id]["current_processes"] = {}


def _serialize_sources() -> list[dict]:
    memory = _read_memory()
    sources = memory.get("sources", [])
    output: list[dict] = []
    for src in sources:
        duration = float(src.get("duration_sec", 0))
        profiles = src.get("profiles", {})
        cursor_sec = _get_source_cursor_sec(src)
        remaining_sec = max(0, math.ceil(duration) - cursor_sec)
        remaining_by_duration = {
            str(seg): max(0, math.ceil(remaining_sec / seg))
            for seg in (30, 45, 60, 90, 120)
        }
        output.append(
            {
                "id": src.get("id"),
                "name": src.get("name"),
                "duration_sec": duration,
                "duration_hhmmss": _format_seconds_to_hhmmss(math.ceil(duration)),
                "created_at": src.get("created_at"),
                "profiles": profiles,
                "cursor_sec": cursor_sec,
                "cursor_hhmmss": _format_seconds_to_hhmmss(cursor_sec),
                "part_counter": int(src.get("part_counter", 0)),
                "remaining_by_duration": remaining_by_duration,
            }
        )
    return output


def _validate_options(segment_seconds: int, shorts_count: int, processing_mode: str) -> tuple[int, int, str]:
    if segment_seconds < 15 or segment_seconds > 600:
        raise HTTPException(status_code=400, detail="Segment duration must be between 15 and 600 seconds.")
    if shorts_count < 1 or shorts_count > 500:
        raise HTTPException(status_code=400, detail="Shorts count must be between 1 and 500.")
    mode = processing_mode.strip().lower()
    if mode not in PROCESSING_MODES:
        raise HTTPException(status_code=400, detail="Processing mode must be 'all_parallel' or 'balanced'.")
    return segment_seconds, shorts_count, mode


def _parse_hhmmss_to_seconds(value: str) -> int:
    """Parse HH:MM:SS or MM:SS into seconds."""
    raw = (value or "").strip()
    if not raw:
        raise HTTPException(status_code=400, detail="Custom start time is empty.")
    parts = raw.split(":")
    if len(parts) == 2:
        hh = 0
        mm, ss = parts
    elif len(parts) == 3:
        hh, mm, ss = parts
    else:
        raise HTTPException(status_code=400, detail="Start time must be HH:MM:SS (or MM:SS).")
    try:
        h = int(hh)
        m = int(mm)
        s = int(ss)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Start time must contain only numbers.") from exc
    if h < 0 or m < 0 or s < 0 or m >= 60 or s >= 60:
        raise HTTPException(status_code=400, detail="Invalid start time range. Use HH:MM:SS.")
    return (h * 3600) + (m * 60) + s


def _resolve_timeline_bounds(
    source: dict,
    duration_sec: float,
    use_custom_start: bool,
    start_time_hhmmss: str | None,
    end_time_hhmmss: str | None,
) -> tuple[int, int]:
    """Resolve start/end timeline bounds from cursor or user-provided custom range."""
    duration_ceiled = math.ceil(float(duration_sec))
    if use_custom_start:
        if not start_time_hhmmss:
            raise HTTPException(status_code=400, detail="Custom start is enabled but no start time was provided.")
        custom_start = _parse_hhmmss_to_seconds(start_time_hhmmss)
        if custom_start >= duration_ceiled:
            raise HTTPException(status_code=400, detail="Custom start time must be inside source duration.")
        if not end_time_hhmmss:
            raise HTTPException(status_code=400, detail="Custom end time is required when custom timeline is enabled.")
        custom_end = _parse_hhmmss_to_seconds(end_time_hhmmss)
        if custom_end <= custom_start:
            raise HTTPException(status_code=400, detail="Custom end time must be greater than custom start time.")
        if custom_end > duration_ceiled:
            raise HTTPException(status_code=400, detail="Custom end time must be inside source duration.")
        return custom_start, custom_end
    cursor = _get_source_cursor_sec(source)
    return cursor, duration_ceiled


def _max_possible_shorts(duration_sec: float, segment_seconds: int) -> int:
    return max(1, math.ceil(float(duration_sec) / float(segment_seconds)))


def _get_source_cursor_sec(source: dict) -> int:
    """Get global timeline cursor; infer for older records without cursor_sec."""
    duration = math.ceil(float(source.get("duration_sec", 0) or 0))
    raw_cursor = source.get("cursor_sec")
    if raw_cursor is not None:
        try:
            return max(0, min(duration, int(raw_cursor)))
        except (TypeError, ValueError):
            pass

    inferred = 0
    profiles = source.get("profiles", {}) or {}
    for dur_key, count in profiles.items():
        try:
            seg = int(dur_key)
            cnt = int(count)
            if seg > 0 and cnt > 0:
                inferred = max(inferred, seg * cnt)
        except (TypeError, ValueError):
            continue
    return max(0, min(duration, inferred))


def _consume_valid_otp(clean_email: str, clean_code: str) -> None:
    _cleanup_expired_otps()
    with AUTH_LOCK:
        conn = _auth_db_connection()
        try:
            row = _db_exec(
                conn,
                "SELECT code, attempts FROM otp_codes WHERE email = ?",
                (clean_email,),
            ).fetchone()
            if row is None:
                raise HTTPException(status_code=400, detail="OTP expired or not requested.")

            attempts = int(row["attempts"] or 0)
            if attempts >= OTP_ATTEMPT_LIMIT:
                _db_exec(conn, "DELETE FROM otp_codes WHERE email = ?", (clean_email,))
                conn.commit()
                raise HTTPException(status_code=400, detail="Too many attempts. Request a new OTP.")

            if str(row["code"] or "") != clean_code:
                _db_exec(conn, "UPDATE otp_codes SET attempts = attempts + 1 WHERE email = ?", (clean_email,))
                conn.commit()
                raise HTTPException(status_code=400, detail="Invalid OTP.")

            _db_exec(conn, "DELETE FROM otp_codes WHERE email = ?", (clean_email,))
            conn.commit()
        finally:
            conn.close()


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path = request.url.path or "/"
    public_prefixes = ("/static", "/clips", "/api/auth")
    if path in {"/", "/login", "/register", "/admin/login"} or path.startswith(public_prefixes):
        return await call_next(request)

    if path.startswith("/api/"):
        if path.startswith("/api/admin/"):
            if _current_admin_from_request(request) is None:
                return JSONResponse({"detail": "Admin authentication required."}, status_code=401)
            return await call_next(request)
        if _current_user_from_request(request) is None:
            return JSONResponse({"detail": "Authentication required."}, status_code=401)
    return await call_next(request)


@app.post("/api/auth/request-otp")
async def auth_request_otp(email: str = Form(...)) -> JSONResponse:
    clean_email = _sanitize_email(email)
    if not clean_email or not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", clean_email):
        raise HTTPException(status_code=400, detail="Enter a valid email address.")

    _cleanup_expired_otps()
    code = f"{secrets.randbelow(10**6):06d}"
    now_iso = _db_iso_now()
    expires_iso = (_utc_now() + timedelta(minutes=OTP_TTL_MINUTES)).isoformat(timespec="seconds") + "Z"
    with AUTH_LOCK:
        conn = _auth_db_connection()
        try:
            _db_exec(
                conn,
                """
                INSERT INTO otp_codes (email, code, expires_at, attempts, created_at)
                VALUES (?, ?, ?, 0, ?)
                ON CONFLICT(email) DO UPDATE SET
                  code=excluded.code,
                  expires_at=excluded.expires_at,
                  attempts=0,
                  created_at=excluded.created_at
                """,
                (clean_email, code, expires_iso, now_iso),
            )
            conn.commit()
        finally:
            conn.close()
    email_sent = False
    smtp_error = ""
    try:
        email_sent = _send_otp_email(clean_email, code)
    except Exception as exc:  # noqa: BLE001
        smtp_error = str(exc) or "Unknown SMTP error."
        print(f"[AUTH] OTP email delivery failed for {clean_email}: {smtp_error}")
    return JSONResponse(
        {
            "ok": True,
            "message": (
                "OTP sent to your email."
                if email_sent
                else ("OTP generated. Email delivery failed; check server console." if smtp_error else "OTP generated. SMTP not configured; check server console.")
            ),
            "email": clean_email,
        }
    )


@app.post("/api/auth/verify-otp")
async def auth_verify_otp(
    email: str = Form(...),
    otp_code: str = Form(...),
) -> JSONResponse:
    clean_email = _sanitize_email(email)
    clean_code = (otp_code or "").strip()
    _consume_valid_otp(clean_email, clean_code)
    user = _get_user_by_email(clean_email)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found. Register first.")
    token = _issue_session(clean_email)

    payload = {
        "ok": True,
        "user": {
            "email": user.get("email"),
            "username": user.get("username"),
            "avatar_url": user.get("avatar_url"),
            "theme": user.get("theme", "dark"),
        },
    }
    res = JSONResponse(payload)
    res.set_cookie(
        SESSION_COOKIE_NAME,
        token,
        httponly=True,
        samesite="lax",
        max_age=int(timedelta(days=SESSION_TTL_DAYS).total_seconds()),
        secure=False,
        path="/",
    )
    return res


@app.post("/api/auth/register")
async def auth_register(
    email: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    otp_code: str = Form(...),
) -> JSONResponse:
    clean_email = _sanitize_email(email)
    clean_code = (otp_code or "").strip()
    _consume_valid_otp(clean_email, clean_code)
    user = _create_user_with_password(clean_email, username, password)

    return JSONResponse(
        {
            "ok": True,
            "message": "Registration successful. Please login.",
            "user": {
                "email": user.get("email"),
                "username": user.get("username"),
            },
        }
    )


@app.post("/api/auth/login")
async def auth_login(
    identifier: str = Form(...),
    password: str = Form(...),
) -> JSONResponse:
    user = _find_user_by_identifier(identifier)
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid credentials.")
    if str(user.get("account_status") or "active") != "active":
        raise HTTPException(status_code=403, detail="This account is paused by admin.")

    if not _verify_password(password or "", str(user.get("password_salt") or ""), str(user.get("password_hash") or "")):
        raise HTTPException(status_code=401, detail="Invalid credentials.")

    token = _issue_session(str(user.get("email", "")))
    res = JSONResponse(
        {
            "ok": True,
            "user": {
                "email": user.get("email"),
                "username": user.get("username"),
                "avatar_url": user.get("avatar_url"),
                "theme": user.get("theme", "dark"),
            },
        }
    )
    res.set_cookie(
        SESSION_COOKIE_NAME,
        token,
        httponly=True,
        samesite="lax",
        max_age=int(timedelta(days=SESSION_TTL_DAYS).total_seconds()),
        secure=False,
        path="/",
    )
    return res


@app.get("/api/auth/me")
async def auth_me(request: Request) -> JSONResponse:
    user = _current_user_from_request(request)
    if user is None:
        return JSONResponse({"authenticated": False, "user": None})
    return JSONResponse(
        {
            "authenticated": True,
            "user": {
                "email": user.get("email"),
                "username": user.get("username"),
                "avatar_url": user.get("avatar_url"),
                "theme": user.get("theme", "dark"),
            },
        }
    )


@app.post("/api/auth/logout")
async def auth_logout(request: Request) -> JSONResponse:
    token = request.cookies.get(SESSION_COOKIE_NAME)
    _invalidate_session(token)
    res = JSONResponse({"ok": True})
    res.delete_cookie(SESSION_COOKIE_NAME, path="/")
    return res


@app.post("/api/auth/profile")
async def auth_update_profile(
    request: Request,
    username: str = Form(""),
    theme: str = Form("dark"),
) -> JSONResponse:
    user = _require_user(request)
    new_user = _upsert_user(
        str(user.get("email", "")),
        username=(username or "").strip() or str(user.get("username") or ""),
        theme=theme if theme in {"dark", "light"} else "dark",
    )
    return JSONResponse(
        {
            "ok": True,
            "user": {
                "email": new_user.get("email"),
                "username": new_user.get("username"),
                "avatar_url": new_user.get("avatar_url"),
                "theme": new_user.get("theme", "dark"),
            },
        }
    )


@app.post("/api/auth/profile/avatar")
async def auth_update_avatar(request: Request, file: UploadFile = File(...)) -> JSONResponse:
    user = _require_user(request)
    if not file.filename:
        raise HTTPException(status_code=400, detail="Select an image file.")
    suffix = Path(file.filename).suffix.lower()
    if suffix not in {".png", ".jpg", ".jpeg", ".webp"}:
        raise HTTPException(status_code=400, detail="Supported formats: PNG, JPG, JPEG, WEBP.")

    email_key = re.sub(r"[^a-z0-9]+", "_", _sanitize_email(str(user.get("email", ""))))
    avatar_name = f"{email_key}_{uuid.uuid4().hex[:8]}{suffix}"
    avatar_path = AVATARS_DIR / avatar_name
    with avatar_path.open("wb") as f:
        shutil.copyfileobj(file.file, f)

    avatar_url = f"/static/avatars/{avatar_name}"
    updated = _upsert_user(str(user.get("email", "")), avatar_url=avatar_url)
    return JSONResponse(
        {
            "ok": True,
            "avatar_url": updated.get("avatar_url"),
            "user": {
                "email": updated.get("email"),
                "username": updated.get("username"),
                "avatar_url": updated.get("avatar_url"),
                "theme": updated.get("theme", "dark"),
            },
        }
    )


@app.get("/", response_class=HTMLResponse)
async def home(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("auth_landing.html", {"request": request, "initial_tab": "login"})


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("auth_landing.html", {"request": request, "initial_tab": "login"})


@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("auth_landing.html", {"request": request, "initial_tab": "register"})


@app.get("/app", response_class=HTMLResponse)
async def app_page(request: Request) -> HTMLResponse:
    if _current_user_from_request(request) is None:
        return RedirectResponse(url="/", status_code=302)
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request) -> HTMLResponse:
    if _current_user_from_request(request) is None:
        return RedirectResponse(url="/", status_code=302)
    return templates.TemplateResponse("settings.html", {"request": request})


@app.get("/admin/login", response_class=HTMLResponse)
async def admin_login_page(request: Request) -> HTMLResponse:
    if _current_admin_from_request(request) is not None:
        return RedirectResponse(url="/admin", status_code=302)
    return templates.TemplateResponse("admin_login.html", {"request": request, "error": ""})


@app.post("/admin/login")
async def admin_login_submit(
    request: Request,
    username: str = Form(""),
    password: str = Form(""),
) -> HTMLResponse:
    clean_username = (username or "").strip()
    if not ADMIN_PANEL_PASSWORD:
        return templates.TemplateResponse(
            "admin_login.html",
            {"request": request, "error": "ADMIN_PANEL_PASSWORD is not configured in .env."},
            status_code=500,
        )
    if clean_username != ADMIN_PANEL_USERNAME or not secrets.compare_digest(password or "", ADMIN_PANEL_PASSWORD):
        return templates.TemplateResponse(
            "admin_login.html",
            {"request": request, "error": "Invalid admin credentials."},
            status_code=401,
        )
    token = _issue_admin_session(clean_username)
    res = RedirectResponse(url="/admin", status_code=302)
    res.set_cookie(
        ADMIN_SESSION_COOKIE_NAME,
        token,
        httponly=True,
        samesite="lax",
        max_age=int(timedelta(hours=ADMIN_SESSION_TTL_HOURS).total_seconds()),
        secure=False,
        path="/",
    )
    return res


@app.post("/admin/logout")
async def admin_logout(request: Request) -> RedirectResponse:
    _invalidate_admin_session(request.cookies.get(ADMIN_SESSION_COOKIE_NAME))
    res = RedirectResponse(url="/admin/login", status_code=302)
    res.delete_cookie(ADMIN_SESSION_COOKIE_NAME, path="/")
    return res


@app.post("/admin/users/action")
async def admin_user_action(
    request: Request,
    email: str = Form(""),
    action: str = Form(""),
) -> RedirectResponse:
    _require_admin(request)
    clean_email = _sanitize_email(email)
    clean_action = (action or "").strip().lower()
    if not clean_email:
        return RedirectResponse(url="/admin?msg=Invalid+email", status_code=302)
    if clean_action == "pause":
        _set_user_account_status(clean_email, "paused")
        return RedirectResponse(url="/admin?msg=User+paused", status_code=302)
    if clean_action == "continue":
        _set_user_account_status(clean_email, "active")
        return RedirectResponse(url="/admin?msg=User+activated", status_code=302)
    if clean_action == "delete":
        _delete_user_account(clean_email)
        return RedirectResponse(url="/admin?msg=User+deleted", status_code=302)
    return RedirectResponse(url="/admin?msg=Invalid+action", status_code=302)


@app.get("/admin", response_class=HTMLResponse)
async def admin_page(request: Request) -> HTMLResponse:
    admin = _current_admin_from_request(request)
    if admin is None:
        return RedirectResponse(url="/admin/login", status_code=302)
    data = _admin_dashboard_data()
    status_msg = request.query_params.get("msg", "")
    return templates.TemplateResponse(
        "admin.html",
        {
            "request": request,
            "admin": admin,
            "metrics": data["metrics"],
            "recent_users": data["recent_users"],
            "recent_sessions": data["recent_sessions"],
            "recent_otps": data["recent_otps"],
            "db_backend": AUTH_DB_BACKEND,
            "status_msg": status_msg,
        },
    )


@app.get("/api/admin/overview")
async def admin_overview(request: Request) -> JSONResponse:
    _require_admin(request)
    return JSONResponse({"ok": True, "backend": AUTH_DB_BACKEND, **_admin_dashboard_data()})


@app.get("/api/sources")
async def list_sources() -> JSONResponse:
    sources = _serialize_sources()
    return JSONResponse({"sources": sources, "capacity": MAX_MEMORY_SOURCES, "used": len(sources)})


@app.post("/api/upload")
async def upload_video(
    file: UploadFile = File(...),
    segment_seconds: int = Form(DEFAULT_SEGMENT_SECONDS),
    shorts_count: int = Form(10),
    processing_mode: str = Form(DEFAULT_PROCESSING_MODE),
    use_custom_start: bool = Form(False),
    start_time_hhmmss: str = Form(""),
    end_time_hhmmss: str = Form(""),
    use_custom_text: bool = Form(DEFAULT_USE_CUSTOM_TEXT),
    text_primary: str = Form(DEFAULT_TEXT_PRIMARY),
    text_secondary: str = Form(DEFAULT_TEXT_SECONDARY),
    font_key: str = Form(DEFAULT_FONT_KEY),
    font_color: str = Form(DEFAULT_FONT_COLOR),
    font_size: int = Form(DEFAULT_FONT_SIZE),
    text_position: str = Form(DEFAULT_TEXT_POSITION),
    part_position: str = Form(DEFAULT_PART_POSITION),
    use_pixel_positioning: bool = Form(False),
    text1_x: int = Form(40),
    text1_y: int = Form(1640),
    text2_x: int = Form(40),
    text2_y: int = Form(1710),
    part_x: int = Form(820),
    part_y: int = Form(40),
) -> JSONResponse:
    segment_seconds, shorts_count, processing_mode = _validate_options(segment_seconds, shorts_count, processing_mode)
    overlay = _validate_overlay_options(
        use_custom_text,
        text_primary,
        text_secondary,
        font_key,
        font_color,
        font_size,
        text_position,
        part_position,
        use_pixel_positioning,
        text1_x,
        text1_y,
        text2_x,
        text2_y,
        part_x,
        part_y,
    )

    if not file.filename:
        raise HTTPException(status_code=400, detail="Please select a video file.")

    memory = _read_memory()
    sources = memory.get("sources", [])
    if len(sources) >= MAX_MEMORY_SOURCES:
        raise HTTPException(status_code=409, detail="Memory full: delete one of the 2 saved uploads before adding a new video.")

    safe_name = Path(file.filename).name
    source_id = uuid.uuid4().hex
    upload_path = UPLOAD_DIR / f"{source_id}_{safe_name}"

    try:
        with upload_path.open("wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
    finally:
        try:
            file.file.close()
        except Exception:
            pass

    duration = _get_video_duration_seconds(upload_path)
    source = {
        "id": source_id,
        "name": safe_name,
        "file_path": str(upload_path),
        "duration_sec": duration,
        "created_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "cursor_sec": 0,
        "part_counter": 0,
        "profiles": {},
    }

    sources.append(source)
    memory["sources"] = sources
    _write_memory(memory)

    start_seconds, end_seconds = _resolve_timeline_bounds(
        source,
        duration,
        use_custom_start,
        start_time_hhmmss,
        end_time_hhmmss,
    )
    remaining_total_seconds = max(0, end_seconds - start_seconds)
    max_possible = max(1, math.ceil(remaining_total_seconds / segment_seconds))
    if remaining_total_seconds <= 0:
        raise HTTPException(status_code=400, detail="No timeline remaining for selected duration.")
    remaining = max_possible
    if shorts_count > remaining:
        raise HTTPException(
            status_code=400,
            detail=f"Requested shorts ({shorts_count}) exceed available count ({remaining}) for {segment_seconds}s duration.",
        )

    job_id = uuid.uuid4().hex
    job = {
        "job_id": job_id,
        "status": "queued",
        "error": None,
        "source_id": source_id,
        "segment_seconds": segment_seconds,
        "requested_count": shorts_count,
        "processing_mode": processing_mode,
        "start_seconds": start_seconds,
        "end_seconds": end_seconds,
        "overlay": overlay,
        "source_duration": duration,
        "source_duration_hhmmss": _format_seconds_to_hhmmss(math.ceil(duration)),
        "total_segments": 0,
        "completed_segments": 0,
        "overall_progress": 0.0,
        "current_segment_index": None,
        "cancel_requested": False,
        "clips": [],
        "current_processes": {},
    }

    with JOBS_LOCK:
        JOBS[job_id] = job

    worker = threading.Thread(
        target=_process_video_job,
        args=(job_id, source, segment_seconds, start_seconds, end_seconds, shorts_count, bool(use_custom_start), overlay),
        daemon=True,
    )
    worker.start()

    return JSONResponse({"job_id": job_id, "source_id": source_id})


@app.post("/api/source/{source_id}/generate")
async def generate_more(source_id: str, payload: GenerateMorePayload) -> JSONResponse:
    segment_seconds, shorts_count, processing_mode = _validate_options(
        payload.segment_seconds,
        payload.shorts_count,
        payload.processing_mode,
    )
    overlay = _validate_overlay_options(
        payload.use_custom_text,
        payload.text_primary,
        payload.text_secondary,
        payload.font_key,
        payload.font_color,
        payload.font_size,
        payload.text_position,
        payload.part_position,
        payload.use_pixel_positioning,
        payload.text1_x,
        payload.text1_y,
        payload.text2_x,
        payload.text2_y,
        payload.part_x,
        payload.part_y,
    )

    memory = _read_memory()
    source = next((src for src in memory.get("sources", []) if src.get("id") == source_id), None)
    if source is None:
        raise HTTPException(status_code=404, detail="Source not found.")

    input_path = Path(str(source.get("file_path", "")))
    if not input_path.exists():
        raise HTTPException(status_code=404, detail="Source video file missing. Delete this record and upload again.")

    start_seconds, end_seconds = _resolve_timeline_bounds(
        source,
        float(source["duration_sec"]),
        bool(payload.use_custom_start),
        payload.start_time_hhmmss,
        payload.end_time_hhmmss,
    )
    remaining_total_seconds = max(0, end_seconds - start_seconds)
    max_possible = max(1, math.ceil(remaining_total_seconds / segment_seconds))
    if remaining_total_seconds <= 0:
        raise HTTPException(status_code=400, detail="All possible shorts for this duration are already generated.")
    remaining = max_possible
    if shorts_count > remaining:
        raise HTTPException(
            status_code=400,
            detail=f"Requested shorts ({shorts_count}) exceed remaining available count ({remaining}) for {segment_seconds}s duration.",
        )

    job_id = uuid.uuid4().hex
    job = {
        "job_id": job_id,
        "status": "queued",
        "error": None,
        "source_id": source_id,
        "segment_seconds": segment_seconds,
        "requested_count": shorts_count,
        "processing_mode": processing_mode,
        "start_seconds": start_seconds,
        "end_seconds": end_seconds,
        "overlay": overlay,
        "source_duration": float(source["duration_sec"]),
        "source_duration_hhmmss": _format_seconds_to_hhmmss(math.ceil(float(source["duration_sec"]))),
        "total_segments": 0,
        "completed_segments": 0,
        "overall_progress": 0.0,
        "current_segment_index": None,
        "cancel_requested": False,
        "clips": [],
        "current_processes": {},
    }

    with JOBS_LOCK:
        JOBS[job_id] = job

    worker = threading.Thread(
        target=_process_video_job,
        args=(job_id, source, segment_seconds, start_seconds, end_seconds, shorts_count, bool(payload.use_custom_start), overlay),
        daemon=True,
    )
    worker.start()

    return JSONResponse({"job_id": job_id, "source_id": source_id})


@app.delete("/api/source/{source_id}")
async def delete_source(source_id: str) -> JSONResponse:
    memory = _read_memory()
    sources = memory.get("sources", [])

    idx = next((i for i, src in enumerate(sources) if src.get("id") == source_id), None)
    if idx is None:
        raise HTTPException(status_code=404, detail="Source not found.")

    source = sources.pop(idx)
    memory["sources"] = sources
    _write_memory(memory)

    file_path = Path(str(source.get("file_path", "")))
    try:
        file_path.unlink(missing_ok=True)
    except OSError:
        pass

    clip_dir = CLIPS_DIR / source_id
    if clip_dir.exists():
        shutil.rmtree(clip_dir, ignore_errors=True)

    return JSONResponse({"ok": True, "source_id": source_id})


@app.get("/api/job/{job_id}")
async def get_job(job_id: str) -> JSONResponse:
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="Job not found.")
        return JSONResponse(_serialize_job(job))


@app.post("/api/cancel/{job_id}")
async def cancel_job(job_id: str) -> JSONResponse:
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="Job not found.")

        job["cancel_requested"] = True
        _terminate_job_processes(job)

    return JSONResponse({"ok": True, "job_id": job_id})


@app.post("/api/downloader/start")
async def start_download_from_link(
    url: str = Form(...),
    source: str = Form("other"),
    output_format: str = Form("mp4"),
    download_profile: str = Form("balanced"),
) -> JSONResponse:
    clean_url, source_key, format_key = _validate_download_inputs(url, source, output_format)
    profile_key = _validate_download_profile(download_profile)

    items = _read_download_memory().get("items", []) or []
    valid_items = [item for item in items if Path(str(item.get("file_path", ""))).exists()]
    with DOWNLOAD_JOBS_LOCK:
        active_jobs = sum(
            1
            for job in DOWNLOAD_JOBS.values()
            if str(job.get("status")) in {"queued", "processing"}
        )
    if len(valid_items) + active_jobs >= MAX_DOWNLOAD_MEMORY_ITEMS:
        raise HTTPException(
            status_code=409,
            detail="Downloader memory full (5/5). Delete one downloaded item before starting a new download.",
        )

    job_id = uuid.uuid4().hex
    request_id = uuid.uuid4().hex
    with DOWNLOAD_JOBS_LOCK:
        DOWNLOAD_JOBS[job_id] = {
            "job_id": job_id,
            "request_id": request_id,
            "status": "queued",
            "progress": 0.0,
            "error": None,
            "url": clean_url,
            "source": source_key,
            "output_format": format_key,
            "file_path": None,
            "file_name": None,
            "media_type": "audio/mpeg" if format_key == "mp3" else "video/mp4",
            "download_profile": profile_key,
            "created_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
            "started_at": None,
            "completed_at": None,
            "stage": "queued",
            "last_log": "Queued",
            "cancel_requested": False,
            "process": None,
        }

    worker = threading.Thread(target=_run_downloader_job, args=(job_id, clean_url, format_key), daemon=True)
    worker.start()
    return JSONResponse({"job_id": job_id})


@app.get("/api/downloader/job/{job_id}")
async def get_downloader_job(job_id: str) -> JSONResponse:
    with DOWNLOAD_JOBS_LOCK:
        job = DOWNLOAD_JOBS.get(job_id)
        if job is not None:
            return JSONResponse(_serialize_download_job(job))

    memory_item = _find_download_memory_item_by_job_id(job_id)
    if memory_item is not None:
        file_name = str(memory_item.get("file_name") or "")
        output_format = str(memory_item.get("output_format") or "")
        payload = {
            "job_id": job_id,
            "status": "completed",
            "progress": 100.0,
            "stage": "completed",
            "last_log": "Recovered from downloader memory.",
            "error": None,
            "output_format": output_format,
            "download_profile": "balanced",
            "file_name": file_name,
            "file_url": f"/api/downloader/file/{job_id}",
            "preview_url": f"/api/downloader/preview/{job_id}",
        }
        return JSONResponse(payload)

    raise HTTPException(status_code=404, detail="Download job not found.")


@app.get("/api/downloader/file/{job_id}")
async def get_downloader_file(job_id: str) -> FileResponse:
    with DOWNLOAD_JOBS_LOCK:
        job = DOWNLOAD_JOBS.get(job_id)
        if job is not None:
            if job.get("status") != "completed":
                raise HTTPException(status_code=409, detail="File is not ready yet.")
            file_path = Path(str(job.get("file_path") or ""))
            filename = str(job.get("file_name") or file_path.name)
            media_type = str(job.get("media_type") or "application/octet-stream")
        else:
            memory_item = _find_download_memory_item_by_job_id(job_id)
            if memory_item is None:
                raise HTTPException(status_code=404, detail="Download job not found.")
            file_path = Path(str(memory_item.get("file_path") or ""))
            filename = str(memory_item.get("file_name") or file_path.name)
            media_type = str(memory_item.get("media_type") or "application/octet-stream")

    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Downloaded file was not found.")
    return FileResponse(path=str(file_path), filename=filename, media_type=media_type)


@app.get("/api/downloader/preview/{job_id}")
async def get_downloader_preview(job_id: str) -> FileResponse:
    with DOWNLOAD_JOBS_LOCK:
        job = DOWNLOAD_JOBS.get(job_id)
        if job is not None:
            if job.get("status") != "completed":
                raise HTTPException(status_code=409, detail="Preview is not ready yet.")
            file_path = Path(str(job.get("file_path") or ""))
            media_type = str(job.get("media_type") or "application/octet-stream")
        else:
            memory_item = _find_download_memory_item_by_job_id(job_id)
            if memory_item is None:
                raise HTTPException(status_code=404, detail="Download job not found.")
            file_path = Path(str(memory_item.get("file_path") or ""))
            media_type = str(memory_item.get("media_type") or "application/octet-stream")

    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Downloaded file was not found.")
    # No attachment filename here, so browser can play media inline.
    return FileResponse(path=str(file_path), media_type=media_type)


@app.post("/api/downloader/cancel/{job_id}")
async def cancel_downloader_job(job_id: str) -> JSONResponse:
    with DOWNLOAD_JOBS_LOCK:
        job = DOWNLOAD_JOBS.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="Download job not found.")
        if str(job.get("status")) not in {"queued", "processing"}:
            return JSONResponse({"ok": True, "job_id": job_id, "status": job.get("status")})

        job["cancel_requested"] = True
        process = job.get("process")
        _terminate_download_process_tree(process)

    return JSONResponse({"ok": True, "job_id": job_id, "status": "cancelling"})


@app.get("/api/downloader/memory")
async def get_downloader_memory() -> JSONResponse:
    items = _serialize_download_memory_items()
    return JSONResponse({"items": items, "capacity": MAX_DOWNLOAD_MEMORY_ITEMS, "used": len(items)})


@app.get("/api/downloader/memory/file/{item_id}")
async def get_downloader_memory_file(item_id: str) -> FileResponse:
    memory = _read_download_memory()
    item = next((it for it in memory.get("items", []) if str(it.get("id")) == item_id), None)
    if item is None:
        raise HTTPException(status_code=404, detail="Downloaded item not found.")
    file_path = Path(str(item.get("file_path", "")))
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Downloaded file missing. Delete memory item and retry.")
    file_name = str(item.get("file_name") or file_path.name)
    media_type = str(item.get("media_type") or "application/octet-stream")
    return FileResponse(path=str(file_path), filename=file_name, media_type=media_type)


@app.get("/api/downloader/memory/preview/{item_id}")
async def get_downloader_memory_preview(item_id: str) -> FileResponse:
    memory = _read_download_memory()
    item = next((it for it in memory.get("items", []) if str(it.get("id")) == item_id), None)
    if item is None:
        raise HTTPException(status_code=404, detail="Downloaded item not found.")
    file_path = Path(str(item.get("file_path", "")))
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Downloaded file missing. Delete memory item and retry.")
    media_type = str(item.get("media_type") or "application/octet-stream")
    return FileResponse(path=str(file_path), media_type=media_type)


@app.delete("/api/downloader/memory/{item_id}")
async def delete_downloader_memory_item(item_id: str) -> JSONResponse:
    memory = _read_download_memory()
    items = list(memory.get("items", []) or [])
    idx = next((i for i, it in enumerate(items) if str(it.get("id")) == item_id), None)
    if idx is None:
        raise HTTPException(status_code=404, detail="Downloaded item not found.")

    item = items.pop(idx)
    memory["items"] = items
    _write_download_memory(memory)

    try:
        Path(str(item.get("file_path", ""))).unlink(missing_ok=True)
    except OSError:
        pass

    return JSONResponse({"ok": True, "item_id": item_id})
