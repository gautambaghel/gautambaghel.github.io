import ipaddress
import os
import random
import re
import smtplib
import sqlite3
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
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
# Max number of uncached public IPs to resolve via external lookup per dashboard
# load. Keeps the request fast while the location cache self-heals over time.
MAX_IP_LOOKUPS_PER_LOAD = 3
# Destination for contact form submissions.
CONTACT_RECIPIENT = os.environ.get("CONTACT_RECIPIENT", "gautambagheldon@gmail.com")


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
                "exclude_bots": "1" if get_toggle_value(request.args.get("exclude_bots")) else "0",
                "residential_only": "1" if get_toggle_value(request.args.get("residential_only")) else "0",
                "top_ips_sort": get_sort_value(request.args.get("top_ips_sort")),
                "top_referrers_sort": get_sort_value(request.args.get("top_referrers_sort")),
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
        exclude_bots = get_toggle_value(request.args.get("exclude_bots"))
        residential_only = get_toggle_value(request.args.get("residential_only"))
        top_ips_sort = get_sort_value(request.args.get("top_ips_sort"))
        top_referrers_sort = get_sort_value(request.args.get("top_referrers_sort"))
        top_paths = get_top_paths(page=top_paths_page, per_page=SUMMARY_PAGE_SIZE, exclude_bots=exclude_bots)
        top_ips = get_top_ips(page=top_ips_page, per_page=SUMMARY_PAGE_SIZE, exclude_private_ips=exclude_private_ips, exclude_bots=exclude_bots, sort=top_ips_sort, residential_only=residential_only)
        top_referrers = get_top_referrers(page=top_referrers_page, per_page=SUMMARY_PAGE_SIZE, exclude_bots=exclude_bots, sort=top_referrers_sort)
        recent_requests = get_recent_requests(page=requests_page, per_page=REQUESTS_PAGE_SIZE)
        recent_logins = get_recent_login_attempts(page=logins_page, per_page=LOGINS_PAGE_SIZE)

        return render_template(
            "admin.html",
            stats=get_dashboard_stats(exclude_bots=exclude_bots),
            top_paths=top_paths["rows"],
            top_paths_pagination=top_paths["pagination"],
            top_ips=top_ips["rows"],
            top_ips_pagination=top_ips["pagination"],
            top_ips_sort=top_ips["sort"],
            exclude_private_ips=exclude_private_ips,
            exclude_bots=exclude_bots,
            residential_only=residential_only,
            top_referrers=top_referrers["rows"],
            top_referrers_pagination=top_referrers["pagination"],
            top_referrers_sort=top_referrers["sort"],
            recent_requests=recent_requests["rows"],
            recent_requests_pagination=recent_requests["pagination"],
            recent_logins=recent_logins["rows"],
            recent_logins_pagination=recent_logins["pagination"],
        )

    @app.route("/admin/ip-lookup", methods=["GET"])
    @login_required
    def ip_lookup():
        query = (request.args.get("ip") or "").strip()
        details = lookup_ip_details(query) if query else None
        return render_template("ip_lookup.html", query=query, details=details)

    @app.route("/health")
    def health():
        return {"status": "ok"}

    @app.route("/api/contact/captcha", methods=["GET"])
    def contact_captcha():
        a = random.randint(1, 9)
        b = random.randint(1, 9)
        session["contact_captcha_answer"] = a + b
        return {"question": f"What is {a} + {b}?"}

    @app.route("/api/contact", methods=["POST"])
    def contact_submit():
        data = request.get_json(silent=True) or {}
        name = (data.get("name") or "").strip()
        email = (data.get("email") or "").strip()
        message = (data.get("message") or "").strip()
        captcha = (str(data.get("captcha") or "")).strip()

        if not name or not email or not message:
            return {"ok": False, "error": "Name, email, and message are required."}, 400
        if not is_valid_email(email):
            return {"ok": False, "error": "Please provide a valid email address."}, 400
        if len(message) > 5000 or len(name) > 200:
            return {"ok": False, "error": "Input is too long."}, 400

        expected = session.get("contact_captcha_answer")
        if expected is None:
            return {"ok": False, "error": "Captcha expired. Please try again."}, 400
        try:
            captcha_ok = int(captcha) == int(expected)
        except (TypeError, ValueError):
            captcha_ok = False
        if not captcha_ok:
            return {"ok": False, "error": "Captcha answer is incorrect."}, 400

        # Captcha consumed regardless of send outcome.
        session.pop("contact_captcha_answer", None)

        try:
            send_contact_email(name=name, email=email, message=message)
        except Exception:
            current_app.logger.exception("Failed to send contact email")
            return {
                "ok": False,
                "error": "Sorry, the message could not be sent right now. Please email directly.",
            }, 500

        return {"ok": True}

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
            looked_up_at TEXT NOT NULL,
            is_datacenter INTEGER
        );

        CREATE INDEX IF NOT EXISTS idx_traffic_timestamp ON traffic_logs (timestamp);
        CREATE INDEX IF NOT EXISTS idx_traffic_path ON traffic_logs (path);
        CREATE INDEX IF NOT EXISTS idx_traffic_referer ON traffic_logs (referer);
        CREATE INDEX IF NOT EXISTS idx_traffic_is_auth ON traffic_logs (is_authenticated);
        CREATE INDEX IF NOT EXISTS idx_login_audit_success ON login_audit (success);
        """
    )
    db.commit()
    ensure_ip_locations_columns(db)


def ensure_ip_locations_columns(db):
    existing = {row["name"] for row in db.execute("PRAGMA table_info(ip_locations)").fetchall()}
    if "is_datacenter" not in existing:
        db.execute("ALTER TABLE ip_locations ADD COLUMN is_datacenter INTEGER")
        db.commit()


def bootstrap_admin_user():
    username = os.environ.get("ADMIN_USERNAME")
    password = os.environ.get("ADMIN_PASSWORD")
    if not username or not password:
        raise RuntimeError(
            "ADMIN_USERNAME and ADMIN_PASSWORD must be set. Refusing to start with "
            "default/blank admin credentials."
        )
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


def get_dashboard_stats(exclude_bots=False):
    db = get_db()
    since_24h = iso_timestamp(datetime.now(timezone.utc) - timedelta(hours=24))

    bots_where = bot_filter_clause(exclude_bots, use_where=True)
    bots_and = bot_filter_clause(exclude_bots, use_where=False)

    total_requests = scalar_query(f"SELECT COUNT(*) FROM traffic_logs{bots_where}")
    requests_last_24h = scalar_query(
        f"SELECT COUNT(*) FROM traffic_logs WHERE timestamp >= ?{bots_and}", (since_24h,)
    )
    authenticated_requests = scalar_query(
        f"SELECT COUNT(*) FROM traffic_logs WHERE is_authenticated = 1{bots_and}"
    )
    failed_logins = scalar_query("SELECT COUNT(*) FROM login_audit WHERE success = 0")

    return {
        "total_requests": total_requests,
        "requests_last_24h": requests_last_24h,
        "authenticated_requests": authenticated_requests,
        "failed_logins": failed_logins,
        "first_seen": db.execute(
            f"SELECT MIN(timestamp) AS value FROM traffic_logs{bots_where}"
        ).fetchone()["value"],
        "last_seen": db.execute(
            f"SELECT MAX(timestamp) AS value FROM traffic_logs{bots_where}"
        ).fetchone()["value"],
    }


# Allowed sort values for the Top IPs / Top Referrers panels. Each maps to a
# (column, direction) pair used to build a safe ORDER BY clause.
SORT_OPTIONS = {
    "hits_desc": ("hits", "DESC"),
    "hits_asc": ("hits", "ASC"),
    "time_desc": ("last_seen", "DESC"),
    "time_asc": ("last_seen", "ASC"),
}
DEFAULT_SORT = "hits_desc"


def get_sort_value(raw_value):
    value = str(raw_value or "").lower().strip()
    return value if value in SORT_OPTIONS else DEFAULT_SORT


def sort_order_clause(sort_value, tiebreaker):
    column, direction = SORT_OPTIONS[get_sort_value(sort_value)]
    return f"ORDER BY {column} {direction}, {tiebreaker} ASC"


def get_top_paths(page=1, per_page=8, exclude_bots=False):
    offset = (page - 1) * per_page
    bots_and = bot_filter_clause(exclude_bots, use_where=False)
    rows = get_db().execute(
        f"""
        SELECT path, COUNT(*) AS hits
        FROM traffic_logs
        WHERE path != '/health'{bots_and}
        GROUP BY path
        ORDER BY hits DESC, path ASC
        LIMIT ? OFFSET ?
        """,
        (per_page, offset),
    ).fetchall()
    total = scalar_query(
        f"SELECT COUNT(DISTINCT path) FROM traffic_logs WHERE path != '/health'{bots_and}"
    )
    return {"rows": rows, "pagination": build_pagination(page, per_page, total, "top_paths_page")}


def get_top_ips(page=1, per_page=8, exclude_private_ips=False, exclude_bots=False, sort=DEFAULT_SORT, residential_only=False):
    bots_where = bot_filter_clause(exclude_bots, use_where=True)
    order_clause = sort_order_clause(sort, tiebreaker="client_ip")
    rows = get_db().execute(
        f"""
        SELECT
            COALESCE(NULLIF(forwarded_for, ''), ip_address, 'unknown') AS client_ip,
            COUNT(*) AS hits,
            MAX(timestamp) AS last_seen
        FROM traffic_logs{bots_where}
        GROUP BY client_ip
        {order_clause}
        """,
    ).fetchall()

    # First pass: normalise + classify (pure in-memory, no DB / network) and apply
    # the private/datacenter filters so pagination is computed on the final set.
    filtered = []
    for row in rows:
        client_ip = normalize_client_ip(row["client_ip"])
        ip_type = classify_client_ip(client_ip)
        if exclude_private_ips and ip_type in {"loopback", "private"}:
            continue
        if residential_only and ip_type == "public" and is_datacenter_ip_cached(client_ip):
            continue
        filtered.append((client_ip, row["hits"], row["last_seen"]))

    total = len(filtered)
    offset = (page - 1) * per_page
    page_slice = filtered[offset: offset + per_page]

    # Only enrich the IPs on the current page, and do it with a single batched
    # query against the location cache instead of one query per IP (N+1).
    locations = get_cached_ip_locations([ip for ip, _, _ in page_slice])

    # Resolve at most a few uncached public IPs per load (bounded, short timeout)
    # so the cache self-heals over time without ever blocking on the full set.
    resolve_budget = MAX_IP_LOOKUPS_PER_LOAD
    for client_ip, _, _ in page_slice:
        if resolve_budget <= 0:
            break
        if client_ip in locations:
            continue
        if classify_client_ip(client_ip) != "public":
            continue
        resolved = fetch_ip_location(client_ip)
        cache_ip_location(client_ip, resolved)
        locations[client_ip] = resolved
        resolve_budget -= 1

    enriched_rows = []
    for client_ip, hits, last_seen in page_slice:
        location = locations.get(client_ip) or get_local_ip_label(client_ip)
        enriched_rows.append(
            {
                "client_ip": client_ip,
                "hits": hits,
                "last_seen": last_seen,
                "label": location["label"],
                "country": location["country"],
                "region": location["region"],
            }
        )

    pagination = build_pagination(page, per_page, total, "top_ips_page")
    return {"rows": enriched_rows, "pagination": pagination, "sort": get_sort_value(sort)}


def get_top_referrers(page=1, per_page=8, exclude_bots=False, sort=DEFAULT_SORT):
    offset = (page - 1) * per_page
    bots_where = bot_filter_clause(exclude_bots, use_where=True)
    order_clause = sort_order_clause(sort, tiebreaker="source")
    rows = get_db().execute(
        f"""
        SELECT
            CASE WHEN referer = '' THEN 'direct / none' ELSE referer END AS source,
            COUNT(*) AS hits,
            MAX(timestamp) AS last_seen
        FROM traffic_logs{bots_where}
        GROUP BY source
        {order_clause}
        LIMIT ? OFFSET ?
        """,
        (per_page, offset),
    ).fetchall()
    total = scalar_query(
        f"SELECT COUNT(*) FROM (SELECT CASE WHEN referer = '' THEN 'direct / none' ELSE referer END AS source FROM traffic_logs{bots_where} GROUP BY source)"
    )
    pagination = build_pagination(page, per_page, total, "top_referrers_page")
    return {"rows": rows, "pagination": pagination, "sort": get_sort_value(sort)}


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


# Substrings that identify automated clients. Matched case-insensitively against
# the User-Agent header. Covers self-identifying crawlers, SEO/monitoring bots,
# headless browsers, and generic HTTP libraries / CLI tools.
BOT_USER_AGENT_MARKERS = (
    "bot",
    "crawl",
    "spider",
    "slurp",
    "headless",
    "python-urllib",
    "python-requests",
    "aiohttp",
    "httpx",
    "curl",
    "wget",
    "go-http-client",
    "java/",
    "okhttp",
    "libwww",
    "scrapy",
    "phantomjs",
    "puppeteer",
    "playwright",
    "facebookexternalhit",
    "embedly",
    "preview",
    "monitor",
    "uptime",
    "pingdom",
    "lighthouse",
    "semrush",
    "ahrefs",
    "mj12",
    "dotbot",
    "petalbot",
    "gptbot",
    "checker",
    "scan",
)


def is_bot_user_agent(user_agent):
    """Return True when the User-Agent looks like a crawler, scraper, or tool."""
    normalized = (user_agent or "").strip().lower()
    if not normalized:
        # A missing UA is a strong signal of an automated/scripted client.
        return True
    return any(marker in normalized for marker in BOT_USER_AGENT_MARKERS)


# SQL fragment used to exclude bot traffic directly inside aggregate queries.
# Kept in sync with BOT_USER_AGENT_MARKERS so both paths agree.
BOT_UA_SQL_CONDITION = (
    "(COALESCE(user_agent, '') = '' OR "
    + " OR ".join(f"LOWER(user_agent) LIKE '%{marker}%'" for marker in BOT_USER_AGENT_MARKERS)
    + ")"
)


def bot_filter_clause(exclude_bots, use_where=True):
    """Return a SQL clause that removes bot traffic when exclude_bots is set."""
    if not exclude_bots:
        return ""
    keyword = "WHERE" if use_where else "AND"
    return f" {keyword} NOT {BOT_UA_SQL_CONDITION}"


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


def get_local_ip_label(ip_address):
    """Resolve label/country/region for an IP WITHOUT any external lookup.

    Used on the dashboard render path: private/loopback/invalid IPs are labelled
    locally, and public IPs fall back to a neutral label if not already cached.
    Never triggers a blocking HTTP request.
    """
    ip_type = classify_client_ip(ip_address)
    if ip_type in {"unknown", "invalid"}:
        return {"label": "Unknown", "country": None, "region": None}
    if ip_type == "loopback":
        return {"label": "LocalHost", "country": None, "region": None}
    if ip_type == "private":
        return {"label": "Private Network", "country": None, "region": None}
    return {"label": "Not yet resolved", "country": None, "region": None}


def get_cached_ip_locations(ip_addresses):
    """Batch-fetch cached locations for many IPs in a single query (avoids N+1).

    Returns a dict keyed by ip_address. Only public IPs are queried; local
    labels are handled by get_local_ip_label at the call site.
    """
    public_ips = [ip for ip in ip_addresses if classify_client_ip(ip) == "public"]
    if not public_ips:
        return {}

    placeholders = ",".join("?" for _ in public_ips)
    rows = get_db().execute(
        f"SELECT ip_address, label, country, region FROM ip_locations WHERE ip_address IN ({placeholders})",
        public_ips,
    ).fetchall()
    return {
        row["ip_address"]: {"label": row["label"], "country": row["country"], "region": row["region"]}
        for row in rows
    }


def is_datacenter_ip_cached(ip_address):
    """Cache-only datacenter check for the render path.

    Unlike is_datacenter_ip(), this never makes an external HTTP request. If the
    flag has not been resolved yet, it conservatively returns False so the IP is
    not filtered out (it can be enriched later by the background pass).
    """
    if classify_client_ip(ip_address) != "public":
        return False
    cached = get_db().execute(
        "SELECT is_datacenter FROM ip_locations WHERE ip_address = ?",
        (ip_address,),
    ).fetchone()
    if cached is not None and cached["is_datacenter"] is not None:
        return bool(cached["is_datacenter"])
    return False


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


def lookup_ip_details(raw_ip):
    """Return a full detail report for a single IP for the admin lookup page.

    Works for private/loopback/invalid IPs (handled locally) and public IPs
    (enriched via ipwho.is for geo and ip-api.com for hosting/proxy flags).
    """
    ip_address = normalize_client_ip(raw_ip)
    ip_type = classify_client_ip(ip_address)

    details = {
        "query": raw_ip,
        "ip_address": ip_address,
        "ip_type": ip_type,
        "is_datacenter": False,
        "is_proxy": False,
        "is_mobile": False,
        "country": None,
        "region": None,
        "city": None,
        "isp": None,
        "org": None,
        "asn": None,
        "as_name": None,
        "timezone": None,
        "reverse": None,
        "sources": [],
        "notes": [],
    }

    if ip_type == "invalid":
        details["notes"].append("Not a valid IPv4/IPv6 address.")
        return details
    if ip_type == "unknown":
        details["notes"].append("No IP address was provided.")
        return details
    if ip_type == "loopback":
        details["notes"].append("Loopback address (localhost). No external lookup performed.")
        return details
    if ip_type == "private":
        details["notes"].append("Private/internal network address (RFC 1918). No external lookup performed.")
        return details

    # Public IP: enrich from external sources.
    whois_data = fetch_ipwhois_details(ip_address)
    if whois_data:
        details.update({k: v for k, v in whois_data.items() if v is not None})
        details["sources"].append("ipwho.is")

    hosting_data = fetch_ipapi_details(ip_address)
    if hosting_data:
        for key in ("country", "region", "city", "isp", "org", "asn", "as_name", "reverse"):
            if not details.get(key) and hosting_data.get(key) is not None:
                details[key] = hosting_data[key]
        if hosting_data.get("is_datacenter") is not None:
            details["is_datacenter"] = hosting_data["is_datacenter"]
        if hosting_data.get("is_proxy") is not None:
            details["is_proxy"] = hosting_data["is_proxy"]
        if hosting_data.get("is_mobile") is not None:
            details["is_mobile"] = hosting_data["is_mobile"]
        details["sources"].append("ip-api.com")

    if not details["sources"]:
        details["notes"].append("External lookups were unavailable. Try again shortly (rate limits may apply).")

    return details


def fetch_ipwhois_details(ip_address):
    try:
        with urllib_request.urlopen(f"https://ipwho.is/{ip_address}", timeout=4) as response:
            payload = json_loads(response.read().decode("utf-8"))
    except (urllib_error.URLError, TimeoutError, ValueError):
        return None

    if not payload.get("success"):
        return None

    connection = payload.get("connection") or {}
    return {
        "country": payload.get("country") or None,
        "region": payload.get("region") or None,
        "city": payload.get("city") or None,
        "timezone": (payload.get("timezone") or {}).get("id") if isinstance(payload.get("timezone"), dict) else None,
        "isp": connection.get("isp") or None,
        "org": connection.get("org") or None,
        "asn": connection.get("asn") or None,
        "as_name": None,
    }


def fetch_ipapi_details(ip_address):
    # ip-api.com free tier is HTTP-only, no key, ~45 req/min. Returns a direct
    # "hosting" boolean that identifies datacenter/cloud IPs.
    fields = "status,message,country,regionName,city,isp,org,as,asname,reverse,proxy,hosting,mobile,query"
    url = f"http://ip-api.com/json/{ip_address}?fields={fields}"
    try:
        with urllib_request.urlopen(url, timeout=4) as response:
            payload = json_loads(response.read().decode("utf-8"))
    except (urllib_error.URLError, TimeoutError, ValueError):
        return None

    if payload.get("status") != "success":
        return None

    asn = None
    as_field = payload.get("as") or ""
    if as_field.upper().startswith("AS"):
        asn = as_field.split(" ", 1)[0][2:] or None

    return {
        "country": payload.get("country") or None,
        "region": payload.get("regionName") or None,
        "city": payload.get("city") or None,
        "isp": payload.get("isp") or None,
        "org": payload.get("org") or None,
        "asn": asn,
        "as_name": payload.get("asname") or None,
        "reverse": payload.get("reverse") or None,
        "is_datacenter": bool(payload.get("hosting")),
        "is_proxy": bool(payload.get("proxy")),
        "is_mobile": bool(payload.get("mobile")),
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


def is_datacenter_ip(ip_address):
    """Return True if a public IP belongs to a datacenter/hosting provider.

    Private, loopback, unknown, and invalid addresses are never datacenters.
    Results are cached in the ip_locations table to avoid repeated ip-api calls.
    """
    if classify_client_ip(ip_address) != "public":
        return False

    cached = get_db().execute(
        "SELECT is_datacenter FROM ip_locations WHERE ip_address = ?",
        (ip_address,),
    ).fetchone()
    if cached is not None and cached["is_datacenter"] is not None:
        return bool(cached["is_datacenter"])

    details = fetch_ipapi_details(ip_address)
    if not details:
        # Lookup unavailable (e.g. rate limited); treat as non-datacenter and
        # leave the cache unset so we can retry later.
        return False

    is_dc = bool(details.get("is_datacenter"))
    store_datacenter_flag(ip_address, is_dc)
    return is_dc


def store_datacenter_flag(ip_address, is_datacenter):
    get_db().execute(
        """
        INSERT INTO ip_locations (ip_address, label, looked_up_at, is_datacenter)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(ip_address) DO UPDATE SET is_datacenter = excluded.is_datacenter
        """,
        (ip_address, "Unknown", utc_now(), 1 if is_datacenter else 0),
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


# Reasonable email validation: local part + domain with a valid TLD.
# Not RFC-exhaustive, but rejects the obviously-malformed addresses that the
# previous "contains @ and ." check let through.
EMAIL_REGEX = re.compile(
    r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+"
    r"@"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}$"
)


def is_valid_email(email):
    if not email or len(email) > 254:
        return False
    if " " in email or ".." in email:
        return False
    if email.startswith(".") or email.startswith("@"):
        return False
    local = email.rsplit("@", 1)[0]
    if local.startswith(".") or local.endswith("."):
        return False
    return EMAIL_REGEX.match(email) is not None


def send_contact_email(name, email, message):
    smtp_host = os.environ.get("SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(os.environ.get("SMTP_PORT", "587"))
    smtp_user = os.environ.get("SMTP_USER")
    smtp_pass = os.environ.get("SMTP_PASS")

    if not smtp_user or not smtp_pass:
        raise RuntimeError("SMTP_USER and SMTP_PASS environment variables are not configured.")

    msg = EmailMessage()
    msg["Subject"] = f"Portfolio contact from {name}"
    msg["From"] = smtp_user
    msg["To"] = CONTACT_RECIPIENT
    msg["Reply-To"] = email
    msg.set_content(
        f"You received a new message from your portfolio contact form.\n\n"
        f"Name: {name}\n"
        f"Email: {email}\n\n"
        f"Message:\n{message}\n"
    )

    with smtplib.SMTP(smtp_host, smtp_port, timeout=20) as server:
        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.send_message(msg)


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
