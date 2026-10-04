# Python TLS certificate monitor — Linux / systemd

Requires Python 3.10+, cryptography, and an SMTP server. Authentication is optional; existing configurations continue to send without authentication.

Checks certificates every hour, warns when 10 days or less remain, and repeats the combined warning every 24 hours. Also reports expired/not-yet-valid certificates and connection failures. Sends a recovery message when all currently configured endpoints are healthy. No cron is required.

## Docker Compose (recommended)

Prebuilt image: `ghcr.io/dkmi/python-cert-monitor:latest` for Linux amd64 and arm64. Docker Engine with the Docker Compose plugin is required. No Python installation or systemd unit is needed on the host.

```bash
git clone https://github.com/dkmi/python-cert-monitor.git
cd python-cert-monitor
mkdir -p config
cp config.json sites.txt config/
```

Edit `config/config.json` with your SMTP relay and email addresses, and `config/sites.txt` with your endpoints. Keep `sites_file` and `state_file` at their default container paths. The `config/` directory is ignored by Git. Files must be readable by container UID 10001 (for example, directory mode 755 and file mode 644).

For SMTP on port **465**, use **"security": "ssl"**. Use `starttls` only with an SMTP port that supports STARTTLS, usually 587 or 25. SMTP authentication is optional; see the section below.

```bash
docker compose pull
docker compose run --rm cert-monitor --dry-run
docker compose run --rm cert-monitor --test-mail
docker compose up -d
docker compose logs -f --tail=100
```

`--dry-run` exits with code 1 if a certificate or endpoint has a problem. It sends no email. `--test-mail` sends a test message without checking endpoints. If GHCR returns an authentication error, the package is private: log in to `ghcr.io` with a GitHub token with `read:packages` access, or build locally as described below. Repository visibility and package visibility are separate settings.

The container runs as UID/GID 10001 with a read-only root filesystem. Configuration is mounted read-only. A named Docker volume persists notification state across restarts and upgrades. No inbound ports are required. The whole config directory is mounted so replacing sites.txt with an editor is picked up on the next scan. Restart after editing config.json:

```bash
docker compose restart cert-monitor
```

Upgrade and stop:

```bash
docker compose pull
docker compose up -d
docker compose down
```

Do not use `docker compose down -v` unless you intend to delete notification state. Logs rotate automatically. For reproducible deployment, replace `latest` in compose.yaml with a published `sha-...` tag or image digest.

### Build locally without registry access

```bash
docker build -t ghcr.io/dkmi/python-cert-monitor:latest .
docker compose up -d --pull never
```

### Migrate from the existing systemd service

Copy your working configuration and endpoint list instead of the examples:

```bash
mkdir -p config
sudo cp /etc/cert-monitor/config.json /etc/cert-monitor/sites.txt config/
sudo chown -R "$(id -u):$(id -g)" config
chmod 755 config
chmod 644 config/config.json config/sites.txt
docker compose pull
docker compose run --rm cert-monitor --dry-run
docker compose run --rm cert-monitor --test-mail
sudo systemctl disable --now cert-monitor.service
docker compose up -d
```

The new volume initially has no notification history, so active warnings will be sent again on the first scan. Keep the old service stopped to avoid duplicate notifications. Existing systemd state is left in place. To roll back, run `docker compose down`, then `sudo systemctl enable --now cert-monitor.service`.

### Image publishing

GitHub Actions smoke-tests the container, including non-root execution, CA certificates, mounted configuration, and persistent state. Successful builds on main publish `latest` and a commit tag to GHCR; version tags such as v1.0.0 publish a versioned image. Pull requests build and test without publishing. Production SMTP delivery must still be tested against your relay.

## Optional SMTP authentication (Docker)

Existing configurations without `smtp.username` continue to work without authentication. For authenticated SMTP, add these fields inside the existing `smtp` object:

```json
"username": "monitor@example.com",
"password_file": "/run/secrets/smtp_password"
```

Keep `security: "ssl"` for port 465, or `starttls` for a STARTTLS-enabled port. Authentication on plain SMTP is rejected. The password file takes precedence over the `SMTP_PASSWORD` environment variable. Missing or empty credentials fail without attempting unauthenticated delivery. Authentication errors do not fall back to relay mode.

Create `secrets/smtp_password.txt` containing only the password (a final newline is allowed). This directory is ignored by Git and excluded from the image. Compose file-backed secrets must be readable by container UID 10001; for example, protect the host directory with mode 700 and give the file mode 644:

```bash
mkdir -p secrets
chmod 700 secrets
nano secrets/smtp_password.txt
chmod 644 secrets/smtp_password.txt
docker compose -f compose.yaml -f compose.auth.yaml pull
docker compose -f compose.yaml -f compose.auth.yaml run --rm cert-monitor --test-mail
docker compose -f compose.yaml -f compose.auth.yaml up -d --force-recreate
```

Use both compose files for subsequent commands in authenticated mode. Keep any existing CA bundle mount/environment settings in compose.yaml; updating the image does not require replacing that file. The SMTP account must be permitted to send as the configured `from` address.

Alternatively, omit `password_file` and pass `SMTP_PASSWORD` into the container using a Compose environment setting. Do not put a password in config.json. To disable authentication, remove `username` or set it to `""`, remove `password_file`, and recreate the container. The default compose.yaml does not require a secret.

## 1. Install without Docker (Debian / Ubuntu)

Extract the archive, enter the python-cert-monitor directory, then run:

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-venv ca-certificates
sudo useradd --system --user-group --home-dir /var/lib/cert-monitor --no-create-home --shell /usr/sbin/nologin cert-monitor
sudo install -d -m 755 /opt/cert-monitor
sudo install -d -m 750 -o root -g cert-monitor /etc/cert-monitor
sudo install -d -m 700 -o cert-monitor -g cert-monitor /var/lib/cert-monitor
sudo install -m 644 monitor.py requirements.txt /opt/cert-monitor/
sudo python3 -m venv /opt/cert-monitor/venv
sudo /opt/cert-monitor/venv/bin/pip install -r /opt/cert-monitor/requirements.txt
sudo install -m 640 -o root -g cert-monitor config.json sites.txt /etc/cert-monitor/
sudo install -m 644 cert-monitor.service /etc/systemd/system/cert-monitor.service
```

Skip useradd if the service account already exists. When upgrading, preserve your existing sites.txt and configuration values instead of overwriting them with the examples.

## 2. Configure

```bash
sudo nano /etc/cert-monitor/sites.txt
sudo nano /etc/cert-monitor/config.json
```

Example sites.txt:

```text
site.example.com
other.example.com:8443
third.example.com:9443
```

Use one hostname or hostname:port per line, without https:// or a path. The default port is 443. Blank lines, comments beginning with #, and IPv6 addresses such as [2001:db8::1]:443 are supported. The file is read on every check, so changes do not require a restart.

sites_file may point to the same file used by the PHP dashboard if the service account can read it and its directory is not blocked by ProtectHome or PrivateTmp.

SMTP configuration:

```json
"smtp": {
  "host": "smtp-relay.example.com",
  "port": 25,
  "security": "none",
  "from": "monitor@example.com",
  "to": ["admin@example.com"]
}
```

Replace the relay hostname and email addresses with your own. Configure the relay to permit sending from the monitoring server's IP address. Omit username or set it to an empty string to send without authentication.

Supported security settings:

- none: plain SMTP, typically port 25; use with your trusted relay.
- starttls: SMTP upgraded to TLS; the relay must support STARTTLS.
- ssl: TLS from the start, typically port 465.

TLS modes validate the SMTP server certificate. Authentication requires ssl or starttls; encryption alone does not enable authentication.

Other settings:

- warning_days: 10 — expiry warning threshold.
- check_interval_seconds: 3600 — delay between completed checks.
- repeat_hours: 24 — minimum interval between combined warning messages.
- timeout_seconds: 10 — network operation timeout; DNS resolution may take longer.

A new problem discovered during the 24-hour reminder interval appears in the next combined warning. There is no separate notification timer per endpoint. With hourly checks, the first expiry warning normally arrives between 9 days 23 hours and 10 days before expiry. Restart the service after changing config.json.

## 3. Check without sending email

```bash
sudo -u cert-monitor /opt/cert-monitor/venv/bin/python /opt/cert-monitor/monitor.py --dry-run
```

Displays certificate information. Exit code 0 means healthy expiry dates; 1 means a warning or check failure. Does not send email or modify state.json.

## 4. Send a test email

```bash
sudo -u cert-monitor /opt/cert-monitor/venv/bin/python /opt/cert-monitor/monitor.py --test-mail
```

Check the recipient inbox and spam folder. SMTP acceptance does not guarantee final delivery. This mode does not check endpoints or modify state.

## 5. Start the service

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now cert-monitor.service
sudo systemctl status cert-monitor.service
sudo journalctl -u cert-monitor.service -f
```

Restart after configuration changes:

```bash
sudo systemctl restart cert-monitor.service
```

Stop and disable:

```bash
sudo systemctl disable --now cert-monitor.service
```

The service checks immediately on startup, then waits for the configured interval after each completed scan. Failed email attempts are retried at the next scan. Notification state is saved atomically after SMTP acceptance. A crash between acceptance and saving may cause a duplicate message. Partial recipient rejection counts as a failure; recipients who accepted the message may receive it again on retry.

--once performs one scan and sends any warning immediately, ignoring the reminder interval, then updates state. Do not run it alongside the service. Exit code 1 indicates endpoint problems; check logs for sending failures.

## Upgrading from the authentication-based package

Replace monitor.py and cert-monitor.service with these versions. Update the smtp section in config.json as shown above; username is optional; omit it to keep sending without authentication. The service no longer reads smtp.env. After installing the updated unit:

```bash
sudo systemctl daemon-reload
sudo systemctl restart cert-monitor.service
```

You may remove the old /etc/cert-monitor/smtp.env file once it is no longer needed. Preserve sites.txt and /var/lib/cert-monitor/state.json.

## Scope

Reads the served leaf certificate using a TLS handshake with SNI. No HTTP request is required. Checks dates, not hostname matching, full chain trust, or revocation. Endpoint certificate retrieval accepts expired and self-signed certificates so their dates can be inspected. SMTP TLS validation is separate and remains enabled in TLS modes.

Behind a CDN or reverse proxy, the visible certificate belongs to that endpoint. Existing acme.json monitoring remains separate; this script does not read acme.json. Add the corresponding public hostname to monitor the certificate actually served.

Checks run sequentially, suitable for a small list. Do not run multiple instances sharing one state_file. If SMTP or the service itself is unavailable, email cannot be sent; failures are recorded in journald.

## Verification

Python syntax, address parsing, state persistence, and mocked SMTP behavior for all three transport modes have been checked. Live TLS/SMTP connections and systemd startup have not been tested in the preparation environment, which lacks cryptography and Linux/systemd. Run --dry-run and --test-mail on your server before enabling the service.
