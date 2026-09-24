#!/usr/bin/env bash
#
# Backup script for the gautam-site portfolio (repo + SQLite DB + secrets).
# Creates a timestamped, owner-only tar.gz snapshot on the 14TB drive and
# prunes old snapshots. Intended to be run by a systemd user timer.
#
set -euo pipefail

# --- Configuration ---------------------------------------------------------
SRC_REPO="/home/gautam/gautambaghel.github.io"
ENV_FILE="/home/gautam/.config/systemd/user/gautam-site.env"
SERVICE_FILE="/home/gautam/.config/systemd/user/gautam-site.service"
DB_FILE="${SRC_REPO}/instance/site.db"

DEST_DIR="/media/gautam/GAUTAM_14TB/backups/gautam-site"
RETENTION=5    # number of snapshots to keep (older ones are auto-pruned)

# --- Preflight -------------------------------------------------------------
if ! mountpoint -q /media/gautam/GAUTAM_14TB; then
    echo "ERROR: /media/gautam/GAUTAM_14TB is not mounted. Aborting." >&2
    exit 1
fi

mkdir -p "$DEST_DIR"

TS="$(date +%Y-%m-%d_%H%M%S)"
STAGE="$(mktemp -d /tmp/gautam-site-backup.XXXXXX)"
trap 'rm -rf "$STAGE"' EXIT

SNAP_ROOT="${STAGE}/gautam-site-${TS}"
mkdir -p "$SNAP_ROOT/repo" "$SNAP_ROOT/secrets"

# --- 1. Repo (excluding the live DB + build/runtime junk) ------------------
# The DB is copied separately below via a consistent SQLite backup.
tar -C "$SRC_REPO" \
    --exclude='./instance/site.db' \
    --exclude='./instance/site.db-wal' \
    --exclude='./instance/site.db-shm' \
    --exclude='./__pycache__' \
    --exclude='./.git' \
    -cf "$SNAP_ROOT/repo/repo.tar" .

# --- 2. Consistent SQLite DB snapshot --------------------------------------
if [ -f "$DB_FILE" ]; then
    python3 - "$DB_FILE" "$SNAP_ROOT/repo/site.db" <<'PY'
import sqlite3, sys
src, dst = sys.argv[1], sys.argv[2]
s = sqlite3.connect(src)
d = sqlite3.connect(dst)
with d:
    s.backup(d)
d.close(); s.close()
print("DB backup OK")
PY
else
    echo "WARNING: DB file $DB_FILE not found; skipping DB snapshot." >&2
fi

# --- 3. Secrets: env vars, passwords, systemd unit -------------------------
[ -f "$ENV_FILE" ]     && cp -a "$ENV_FILE"     "$SNAP_ROOT/secrets/gautam-site.env"
[ -f "$SERVICE_FILE" ] && cp -a "$SERVICE_FILE" "$SNAP_ROOT/secrets/gautam-site.service"

# Record git HEAD so we know exactly which commit was live.
if git -C "$SRC_REPO" rev-parse HEAD >/dev/null 2>&1; then
    git -C "$SRC_REPO" rev-parse HEAD > "$SNAP_ROOT/GIT_HEAD.txt"
    git -C "$SRC_REPO" log -1 --oneline >> "$SNAP_ROOT/GIT_HEAD.txt"
fi

# --- 4. Pack the whole snapshot into one owner-only tarball ----------------
ARCHIVE="${DEST_DIR}/gautam-site-backup-${TS}.tar.gz"
tar -C "$STAGE" -czf "$ARCHIVE" "gautam-site-${TS}"
chmod 600 "$ARCHIVE"

echo "Backup written: $ARCHIVE ($(du -h "$ARCHIVE" | cut -f1))"

# --- 5. Prune old snapshots ------------------------------------------------
mapfile -t OLD < <(ls -1t "${DEST_DIR}"/gautam-site-backup-*.tar.gz 2>/dev/null | tail -n +$((RETENTION + 1)))
for f in "${OLD[@]:-}"; do
    [ -n "$f" ] && { rm -f "$f"; echo "Pruned old backup: $f"; }
done

echo "Done. $(ls -1 "${DEST_DIR}"/gautam-site-backup-*.tar.gz 2>/dev/null | wc -l) snapshot(s) retained."
