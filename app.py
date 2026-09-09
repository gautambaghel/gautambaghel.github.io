import ipaddress
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from urllib import error as urllib_error
from urllib import request as urllib_request

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
REQUESTS_PAGE_SIZE = 25
LOGINS_PAGE_SIZE = 15
SUMMARY_PAGE_SIZE = 8


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
        def admin_url(**updates):
            params = {
                "top_paths_page": get_page_number(request.args.get("top_paths_page")),
                "top_ips_page": get_page_number(request.args.get("top_ips_page")),
                "top_referrers_page": get_page_number(request.args.get("top_referrers_page")),
                "requests_page": get_page_number(request.args.get("requests_page")),
                "logins_page": get_page_number(request.args.get("logins_page")),
                "exclude_private_ips": "1" if get_toggle_value(request.args.get("exclude_private_ips")) else "0",
            }
            params.update(updates)
            return url_for("admin", **params)

        return {
            "is_authenticated": bool(session.get("user_id")),
            "admin_username": session.get("username"),
            "admin_url": admin_url,
        }

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
        top_paths_page = get_page_number(request.args.get("top_paths_page"))
        top_ips_page = get_page_number(request.args.get("top_ips_page"))
        top_referrers_page = get_page_number(request.args.get("top_referrers_page"))
        requests_page = get_page_number(request.args.get("requests_page"))
        logins_page = get_page_number(request.args.get("logins_page"))
        exclude_private_ips = get_toggle_value(request.args.get("exclude_private_ips"))
        top_paths = get_top_paths(page=top_paths_page, per_page=SUMMARY_PAGE_SIZE)
        top_ips = get_top_ips(page=top_ips_page, per_page=SUMMARY_PAGE_SIZE, exclude_private_ips=exclude_private_ips)
        top_referrers = get_top_referrers(page=top_referrers_page, per_page=SUMMARY_PAGE_SIZE)
        recent_requests = get_recent_requests(page=requests_page, per_page=REQUESTS_PAGE_SIZE)
        recent_logins = get_recent_login_attempts(page=logins_page, per_page=LOGINS_PAGE_SIZE)

        return render_template(
            "admin.html",
            stats=get_dashboard_stats(),
            top_paths=top_paths["rows"],
            top_paths_pagination=top_paths["pagination"],
            top_ips=top_ips["rows"],
            top_ips_pagination=top_ips["pagination"],
            exclude_private_ips=exclude_private_ips,
            top_referrers=top_referrers["rows"],
            top_referrers_pagination=top_referrers["pagination"],
            recent_requests=recent_requests["rows"],
            recent_requests_pagination=recent_requests["pagination"],
            recent_logins=recent_logins["rows"],
            recent_logins_pagination=recent_logins["pagination"],
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

        CREATE TABLE IF NOT EXISTS ip_locations (
            ip_address TEXT PRIMARY KEY,
            label TEXT NOT NULL,
            country TEXT,
            region TEXT,
            looked_up_at TEXT NOT NULL
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


def get_top_paths(page=1, per_page=8):
    offset = (page - 1) * per_page
    rows = get_db().execute(
        """
        SELECT path, COUNT(*) AS hits
        FROM traffic_logs
        WHERE path != '/health'
        GROUP BY path
        ORDER BY hits DESC, path ASC
        LIMIT ? OFFSET ?
        """,
        (per_page, offset),
    ).fetchall()
    total = scalar_query("SELECT COUNT(DISTINCT path) FROM traffic_logs WHERE path != '/health'")
    return {"rows": rows, "pagination": build_pagination(page, per_page, total, "top_paths_page")}


def get_top_ips(page=1, per_page=8, exclude_private_ips=False):
    rows = get_db().execute(
        """
        SELECT COALESCE(NULLIF(forwarded_for, ''), ip_address, 'unknown') AS client_ip, COUNT(*) AS hits
        FROM traffic_logs
        GROUP BY client_ip
        ORDER BY hits DESC, client_ip ASC
        """,
    ).fetchall()

    enriched_rows = []
    for row in rows:
        client_ip = normalize_client_ip(row["client_ip"])
        ip_type = classify_client_ip(client_ip)
        if exclude_private_ips and ip_type in {"loopback", "private"}:
            continue
        location = get_ip_location(client_ip)
        enriched_rows.append(
            {
                "client_ip": client_ip,
                "hits": row["hits"],
                "label": location["label"],
                "country": location["country"],
                "region": location["region"],
            }
        )

    total = len(enriched_rows)
    offset = (page - 1) * per_page
    paged_rows = enriched_rows[offset: offset + per_page]

    return {"rows": paged_rows, "pagination": build_pagination(page, per_page, total, "top_ips_page")}


def get_top_referrers(page=1, per_page=8):
    offset = (page - 1) * per_page
    rows = get_db().execute(
        """
        SELECT CASE WHEN referer = '' THEN 'direct / none' ELSE referer END AS source, COUNT(*) AS hits
        FROM traffic_logs
        GROUP BY source
        ORDER BY hits DESC, source ASC
        LIMIT ? OFFSET ?
        """,
        (per_page, offset),
    ).fetchall()
    total = scalar_query(
        "SELECT COUNT(*) FROM (SELECT CASE WHEN referer = '' THEN 'direct / none' ELSE referer END AS source FROM traffic_logs GROUP BY source)"
    )
    return {"rows": rows, "pagination": build_pagination(page, per_page, total, "top_referrers_page")}


def get_recent_requests(page=1, per_page=25):
    offset = (page - 1) * per_page
    rows = get_db().execute(
        """
        SELECT timestamp, method, path, status_code, ip_address, forwarded_for, referer, user_agent, is_authenticated
        FROM traffic_logs
        ORDER BY id DESC
        LIMIT ? OFFSET ?
        """,
        (per_page, offset),
    ).fetchall()
    total = scalar_query("SELECT COUNT(*) FROM traffic_logs")
    return {"rows": rows, "pagination": build_pagination(page, per_page, total, "requests_page")}


def get_recent_login_attempts(page=1, per_page=15):
    offset = (page - 1) * per_page
    rows = get_db().execute(
        """
        SELECT timestamp, username, success, ip_address, user_agent
        FROM login_audit
        ORDER BY id DESC
        LIMIT ? OFFSET ?
        """,
        (per_page, offset),
    ).fetchall()
    total = scalar_query("SELECT COUNT(*) FROM login_audit")
    return {"rows": rows, "pagination": build_pagination(page, per_page, total, "logins_page")}


def scalar_query(query, params=()):
    row = get_db().execute(query, params).fetchone()
    return row[0] if row else 0


def get_page_number(raw_value):
    try:
        page = int(raw_value or "1")
    except (TypeError, ValueError):
        return 1
    return page if page > 0 else 1


def get_toggle_value(raw_value):
    return str(raw_value or "0").lower() in {"1", "true", "yes", "on"}


def build_pagination(page, per_page, total_items, page_param):
    total_pages = max(1, (total_items + per_page - 1) // per_page)
    current_page = min(page, total_pages)
    pages = build_page_links(current_page, total_pages)
    return {
        "page": current_page,
        "per_page": per_page,
        "total_items": total_items,
        "total_pages": total_pages,
        "pages": pages,
        "has_previous": current_page > 1,
        "has_next": current_page < total_pages,
        "previous_page": current_page - 1,
        "next_page": current_page + 1,
        "page_param": page_param,
    }


def build_page_links(current_page, total_pages):
    if total_pages <= 4:
        return [{"kind": "page", "value": page} for page in range(1, total_pages + 1)]

    visible_pages = {1, 2, 3, total_pages}

    if current_page == total_pages:
        visible_pages.update({max(1, total_pages - 3), max(1, total_pages - 2), max(1, total_pages - 1)})

    pages = []
    previous_page = None
    for page in sorted(visible_pages):
        if previous_page is not None and page - previous_page > 1:
            pages.append({"kind": "ellipsis", "value": None})
        pages.append({"kind": "page", "value": page})
        previous_page = page

    return pages


def normalize_client_ip(value):
    raw_value = (value or "unknown").strip()
    if not raw_value:
        return "unknown"
    return raw_value.split(",", 1)[0].strip()


def classify_client_ip(ip_address):
    if ip_address in {"unknown", ""}:
        return "unknown"

    try:
        parsed_ip = ipaddress.ip_address(ip_address)
    except ValueError:
        return "invalid"

    if parsed_ip.is_loopback:
        return "loopback"
    if parsed_ip.is_private:
        return "private"
    return "public"


def get_ip_location(ip_address):
    ip_type = classify_client_ip(ip_address)
    if ip_type in {"unknown", "invalid"}:
        return {"label": "Unknown", "country": None, "region": None}
    if ip_type == "loopback":
        return {"label": "LocalHost", "country": None, "region": None}
    if ip_type == "private":
        return {"label": "Private Network", "country": None, "region": None}

    cached_location = get_cached_ip_location(ip_address)
    if cached_location:
        return cached_location

    location = fetch_ip_location(ip_address)
    cache_ip_location(ip_address, location)
    return location


def get_cached_ip_location(ip_address):
    row = get_db().execute(
        "SELECT label, country, region FROM ip_locations WHERE ip_address = ?",
        (ip_address,),
    ).fetchone()
    if not row:
        return None

    return {
        "label": row["label"],
        "country": row["country"],
        "region": row["region"],
    }


def fetch_ip_location(ip_address):
    lookup_url = f"https://ipwho.is/{ip_address}"
    try:
        with urllib_request.urlopen(lookup_url, timeout=3) as response:
            payload = json_loads(response.read().decode("utf-8"))
    except (urllib_error.URLError, TimeoutError, ValueError):
        return {"label": "Lookup unavailable", "country": None, "region": None}

    if not payload.get("success"):
        return {"label": "Lookup unavailable", "country": None, "region": None}

    country = payload.get("country") or None
    region = payload.get("region") or None

    return {
        "label": build_location_label(country, region) or "Lookup unavailable",
        "country": country,
        "region": region,
    }


def cache_ip_location(ip_address, location):
    get_db().execute(
        """
        INSERT INTO ip_locations (ip_address, label, country, region, looked_up_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(ip_address) DO UPDATE SET
            label = excluded.label,
            country = excluded.country,
            region = excluded.region,
            looked_up_at = excluded.looked_up_at
        """,
        (ip_address, location["label"], location["country"], location["region"], utc_now()),
    )
    get_db().commit()


def build_location_label(country, region):
    parts = [part for part in [region, country] if part]
    return ", ".join(parts)


def json_loads(raw_value):
    import json

    return json.loads(raw_value)


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
