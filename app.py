import os
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

from flask import (
    Flask,
    abort,
    current_app,
    g,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import safe_join


BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"
DATABASE_PATH = INSTANCE_DIR / "site.db"
ALLOWED_STATIC_DIRS = {"assets", "blogs", "downloadables", "images"}
ALLOWED_STATIC_FILES = {"index.html", "blog.html", "post.html", "CNAME", "favicon.ico"}


def create_app():
    app = Flask(__name__, static_folder=None, template_folder="templates")
    app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "dev-change-me")
    app.config["DATABASE"] = str(DATABASE_PATH)
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = os.environ.get("FLASK_SECURE_COOKIE", "false").lower() == "true"

    INSTANCE_DIR.mkdir(exist_ok=True)

    with app.app_context():
        init_db()
        bootstrap_admin_user()

    @app.after_request
    def log_request(response):
        record_traffic(response.status_code)
        return response

    @app.context_processor
    def inject_auth_state():
        return {"is_authenticated": bool(session.get("user_id")), "admin_username": session.get("username")}

    @app.route("/")
    def home():
        return send_root_file("index.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if session.get("user_id"):
            return redirect(url_for("admin"))

        error = None
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            user = get_user_by_username(username)
            authenticated = bool(user and check_password_hash(user["password_hash"], password))

            record_login_attempt(username=username, success=authenticated)

            if authenticated:
                session.clear()
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                update_last_login(user["id"])
                return redirect(url_for("admin"))

            error = "Invalid username or password."

        return render_template("login.html", error=error)

    @app.route("/logout", methods=["POST"])
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.route("/admin")
    @login_required
    def admin():
        return render_template(
            "admin.html",
            stats=get_dashboard_stats(),
            top_paths=get_top_paths(),
            top_ips=get_top_ips(),
            top_referrers=get_top_referrers(),
            recent_requests=get_recent_requests(),
            recent_logins=get_recent_login_attempts(),
        )

    @app.route("/health")
    def health():
        return {"status": "ok"}

    @app.route("/<path:requested_path>")
    def site_files(requested_path):
        return serve_site_path(requested_path)

    return app


def get_db():
    if "db" not in g:
        connection = sqlite3.connect(current_app.config["DATABASE"])
        connection.row_factory = sqlite3.Row
        g.db = connection
    return g.db


def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_login_at TEXT
        );

        CREATE TABLE IF NOT EXISTS traffic_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            method TEXT NOT NULL,
            path TEXT NOT NULL,
            query_string TEXT,
            status_code INTEGER NOT NULL,
            ip_address TEXT,
            forwarded_for TEXT,
            user_agent TEXT,
            referer TEXT,
            is_authenticated INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS login_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            username TEXT,
            success INTEGER NOT NULL,
            ip_address TEXT,
            user_agent TEXT
        );
        """
    )
    db.commit()


def bootstrap_admin_user():
    username = os.environ.get("ADMIN_USERNAME", "admin")
    password = os.environ.get("ADMIN_PASSWORD", "admin123")
    sync_password = os.environ.get("ADMIN_SYNC_PASSWORD", "false").lower() == "true"
    db = get_db()
    existing_user = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    if existing_user:
        if sync_password:
            db.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (generate_password_hash(password), existing_user["id"]),
            )
            db.commit()
        return

    db.execute(
        "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
        (username, generate_password_hash(password), utc_now()),
    )
    db.commit()


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped_view


def get_user_by_username(username):
    return get_db().execute(
        "SELECT id, username, password_hash FROM users WHERE username = ?",
        (username,),
    ).fetchone()


def update_last_login(user_id):
    db = get_db()
    db.execute("UPDATE users SET last_login_at = ? WHERE id = ?", (utc_now(), user_id))
    db.commit()


def record_login_attempt(username, success):
    db = get_db()
    db.execute(
        """
        INSERT INTO login_audit (timestamp, username, success, ip_address, user_agent)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            utc_now(),
            username,
            1 if success else 0,
            get_client_ip(),
            request.headers.get("User-Agent", ""),
        ),
    )
    db.commit()


def record_traffic(status_code):
    db = get_db()
    db.execute(
        """
        INSERT INTO traffic_logs (
            timestamp,
            method,
            path,
            query_string,
            status_code,
            ip_address,
            forwarded_for,
            user_agent,
            referer,
            is_authenticated
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            utc_now(),
            request.method,
            request.path,
            request.query_string.decode("utf-8", errors="ignore"),
            status_code,
            request.remote_addr,
            request.headers.get("X-Forwarded-For", ""),
            request.headers.get("User-Agent", ""),
            request.headers.get("Referer", ""),
            1 if session.get("user_id") else 0,
        ),
    )
    db.commit()


def get_dashboard_stats():
    db = get_db()
    since_24h = iso_timestamp(datetime.now(timezone.utc) - timedelta(hours=24))

    total_requests = scalar_query("SELECT COUNT(*) FROM traffic_logs")
    requests_last_24h = scalar_query("SELECT COUNT(*) FROM traffic_logs WHERE timestamp >= ?", (since_24h,))
    authenticated_requests = scalar_query("SELECT COUNT(*) FROM traffic_logs WHERE is_authenticated = 1")
    failed_logins = scalar_query("SELECT COUNT(*) FROM login_audit WHERE success = 0")

    return {
        "total_requests": total_requests,
        "requests_last_24h": requests_last_24h,
        "authenticated_requests": authenticated_requests,
        "failed_logins": failed_logins,
        "first_seen": db.execute("SELECT MIN(timestamp) AS value FROM traffic_logs").fetchone()["value"],
        "last_seen": db.execute("SELECT MAX(timestamp) AS value FROM traffic_logs").fetchone()["value"],
    }


def get_top_paths(limit=10):
    return get_db().execute(
        """
        SELECT path, COUNT(*) AS hits
        FROM traffic_logs
        GROUP BY path
        ORDER BY hits DESC, path ASC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()


def get_top_ips(limit=10):
    return get_db().execute(
        """
        SELECT COALESCE(NULLIF(forwarded_for, ''), ip_address, 'unknown') AS client_ip, COUNT(*) AS hits
        FROM traffic_logs
        GROUP BY client_ip
        ORDER BY hits DESC, client_ip ASC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()


def get_top_referrers(limit=10):
    return get_db().execute(
        """
        SELECT CASE WHEN referer = '' THEN 'direct / none' ELSE referer END AS source, COUNT(*) AS hits
        FROM traffic_logs
        GROUP BY source
        ORDER BY hits DESC, source ASC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()


def get_recent_requests(limit=100):
    return get_db().execute(
        """
        SELECT timestamp, method, path, status_code, ip_address, forwarded_for, referer, user_agent, is_authenticated
        FROM traffic_logs
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()


def get_recent_login_attempts(limit=25):
    return get_db().execute(
        """
        SELECT timestamp, username, success, ip_address, user_agent
        FROM login_audit
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()


def scalar_query(query, params=()):
    row = get_db().execute(query, params).fetchone()
    return row[0] if row else 0


def serve_site_path(requested_path):
    normalized_path = requested_path.strip("/")
    if normalized_path in ALLOWED_STATIC_FILES:
        return send_root_file(normalized_path)

    first_segment = normalized_path.split("/", 1)[0]
    if first_segment not in ALLOWED_STATIC_DIRS:
        abort(404)

    safe_path = safe_join(str(BASE_DIR), normalized_path)
    if not safe_path or not Path(safe_path).is_file():
        abort(404)

    return send_from_directory(BASE_DIR, normalized_path)


def send_root_file(filename):
    return send_from_directory(BASE_DIR, filename)


def get_client_ip():
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        return forwarded_for.split(",", 1)[0].strip()
    return request.remote_addr or ""


def utc_now():
    return iso_timestamp(datetime.now(timezone.utc))


def iso_timestamp(value):
    return value.replace(microsecond=0).isoformat()


app = create_app()
app.teardown_appcontext(close_db)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8888")))
