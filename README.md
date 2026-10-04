# Python TLS certificate monitor — Linux / systemd

Requires Python 3.10+, cryptography, and an SMTP relay that accepts mail from this server without authentication. No username, password, or SMTP AUTH is used.

Checks certificates every hour, warns when 10 days or less remain, and repeats the combined warning every 24 hours. Also reports expired/not-yet-valid certificates and connection failures. Sends a recovery message when all currently configured endpoints are healthy. No cron is required.

## 1. Install (Debian / Ubuntu)

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

Replace the relay hostname and email addresses with your own. Configure the relay to permit sending from the monitoring server's IP address. Authentication is never attempted.

Supported security settings:

- none: plain SMTP, typically port 25; use with your trusted relay.
- starttls: SMTP upgraded to TLS; the relay must support STARTTLS.
- ssl: TLS from the start, typically port 465.

TLS modes validate the SMTP server certificate. Encryption settings do not enable authentication.

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

Replace monitor.py and cert-monitor.service with these versions. Update the smtp section in config.json as shown above; username is no longer used. The service no longer reads smtp.env. After installing the updated unit:

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
