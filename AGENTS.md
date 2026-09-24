# AGENTS.md

## Project

Personal portfolio website for Gautam Baghel. Vanilla HTML/CSS/JS frontend with a
Flask backend (blog, markdown posts, SQLite in `instance/site.db`).

## Deployment / Server

The site runs as a **Docker container named `gautam-site`** (image `gautam-site:latest`),
served by gunicorn on **port 8888** (`0.0.0.0:8888->8888`).

- Restart the server: `docker restart gautam-site`
- Check status: `docker ps --filter "name=gautam-site"`
- View logs: `docker logs -f gautam-site`

### Applying code/asset changes (rebuild)

The image bakes files in via `COPY . .`, so a plain restart does NOT pick up edits.
After changing HTML/CSS/JS/images/`app.py`/`templates/`, rebuild and recreate:

```bash
cd /home/gautam/gautambaghel.github.io
docker build -t gautam-site:latest .
docker rm -f gautam-site
docker run -d --name gautam-site --restart unless-stopped \
  -p 8888:8888 \
  --env-file /home/gautam/.config/systemd/user/gautam-site.env \
  -v /home/gautam/gautambaghel.github.io/instance:/app/instance \
  gautam-site:latest
```

- **Required env vars** (ADMIN_USERNAME/PASSWORD, FLASK_SECRET_KEY, etc.) live in
  `~/.config/systemd/user/gautam-site.env`. The app refuses to boot without admin creds.
- **Bind mount:** only `instance/` (SQLite DB) is mounted; everything else is baked in.
- A `gautam-site.service` systemd unit also exists (runs gunicorn directly on the host,
  not Docker) but is **disabled**; the Docker container is the active deployment.

### Repo files

`app.py`, `requirements.txt`, `Dockerfile`, `.dockerignore`, and `templates/` are present in
the working dir (needed for `docker build`). `instance/` and `__pycache__/` are gitignored
runtime/build artifacts.

## Local Development (static only)

```bash
python3 -m http.server 8080
```

## Notes

- Favicon: `images/favicon.svg` (primary) + `images/favicon.png` (fallback), referenced with
  `?v=N` cache-busting in `index.html`, `blog.html`, `post.html`. Bump the version when changing.
- No image conversion tools (rsvg/imagemagick/inkscape) are installed; use Pillow to regenerate
  the PNG from the SVG design if needed.
