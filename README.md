# gautambaghel.github.io

Personal portfolio website for Gautam Baghel - Senior Product Manager at HashiCorp.

## Features

- Modern dark theme with gradient accents
- Blog section with category filtering and markdown support
- Accessible blog reader with font controls and high contrast mode
- Fully responsive design

## Tech Stack

- Vanilla HTML, CSS, JavaScript
- Flask for admin authentication and traffic logging
- SQLite for request and login audit storage
- No frontend build process required

## Local Development

Install the Python dependencies:

```bash
python3 -m pip install -r requirements.txt
python3 -m pip install --user gunicorn
```

Set the admin credentials and a Flask secret key before starting the server:

```bash
export ADMIN_USERNAME="admin"
export ADMIN_PASSWORD="change-me"
export FLASK_SECRET_KEY="replace-this-with-a-long-random-string"
```

Run the app on port `8888`:

```bash
python3 app.py
```

Then visit:

- `http://localhost:8888/` for the public site
- `http://localhost:8888/login` for the admin login

## Database

The application creates a SQLite database automatically at `instance/site.db` on first run.

It stores:

- the admin user
- traffic logs for incoming requests
- login success and failure audit events

## Managed Service

The site is configured to run as a user-level `systemd` service:

- service file: `~/.config/systemd/user/gautam-site.service`
- environment file: `~/.config/systemd/user/gautam-site.env`

The service uses `gunicorn` on port `8888`.

Useful commands:

```bash
systemctl --user status gautam-site.service
systemctl --user restart gautam-site.service
journalctl --user -u gautam-site.service -f
```

## Admin Credential Rotation

The managed service reads the admin password from `~/.config/systemd/user/gautam-site.env`.

To rotate the password:

1. Update `ADMIN_PASSWORD` in the env file.
2. Leave `ADMIN_SYNC_PASSWORD=true` enabled.
3. Restart the service with `systemctl --user restart gautam-site.service`.

On startup, the app re-hashes the password from the env file into SQLite so the new password takes effect immediately.

## License

See [LICENSE](LICENSE) for details.
