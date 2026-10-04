#!/usr/bin/env python3
"""TLS expiry monitor. Python 3.10+, cryptography."""
import argparse
import json
import logging
import os
import signal
import smtplib
import socket
import ssl
import threading
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID

STOP = threading.Event()
LOG = logging.getLogger('cert-monitor')


def parse_target(value):
    if value.startswith('['):
        end = value.find(']')
        if end < 0:
            raise ValueError('Invalid IPv6 target')
        host, suffix = value[1:end], value[end + 1:]
        if suffix and not suffix.startswith(':'):
            raise ValueError('Invalid port syntax')
        port = int(suffix[1:]) if suffix else 443
    else:
        if value.count(':') > 1:
            raise ValueError('Use [IPv6]:port')
        parts = value.split(':')
        host, port = parts[0], int(parts[1]) if len(parts) == 2 else 443
    if not host or any(c.isspace() for c in host) or any(c in host for c in '/?#@'):
        raise ValueError('Use hostname[:port], without https:// or path')
    if not 1 <= port <= 65535:
        raise ValueError('Port must be 1..65535')
    return host.encode('idna').decode('ascii'), port


def cert_time(cert, name):
    utc_value = getattr(cert, name + '_utc', None)
    return utc_value if utc_value is not None else getattr(cert, name).replace(tzinfo=timezone.utc)


def check_target(target, warning_days, timeout):
    try:
        host, port = parse_target(target)
        # Read metadata even for expired/self-signed certificates.
        # This is an expiry check, not a certificate trust/hostname check.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as tcp:
            with context.wrap_socket(tcp, server_hostname=host) as tls:
                cert = x509.load_der_x509_certificate(tls.getpeercert(binary_form=True))
        expires = cert_time(cert, 'not_valid_after')
        starts = cert_time(cert, 'not_valid_before')
        now = datetime.now(timezone.utc)
        days = (expires - now).total_seconds() / 86400
        status = 'OK'
        if days <= 0:
            status = 'EXPIRED'
        elif starts > now:
            status = 'NOT YET VALID'
        elif days <= warning_days:
            status = 'EXPIRING'
        common_names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        subject = common_names[0].value if common_names else cert.subject.rfc4514_string()
        text = (f'{target} | {status} | {days:.1f} days\n'
                f'  Certificate: {subject}\n  Issuer: {cert.issuer.rfc4514_string()}\n'
                f'  Expires: {expires.isoformat()}')
        return status != 'OK', text
    except Exception as exc:
        return True, f'{target} | CHECK FAILED | {type(exc).__name__}: {exc}'


def scan(config):
    try:
        lines = Path(config['sites_file']).read_text(encoding='utf-8-sig').splitlines()
        targets = list(dict.fromkeys(line.strip() for line in lines
                                    if line.strip() and not line.strip().startswith('#')))
        if not targets:
            raise ValueError('sites.txt is empty')
    except Exception as exc:
        return [f'SITES FILE ERROR: {exc}'], []
    alerts, reports = [], []
    for target in targets:
        if STOP.is_set():
            break
        problem, report = check_target(target, config['warning_days'], config['timeout_seconds'])
        reports.append(report)
        LOG.info('%s', report)
        if problem:
            alerts.append(report)
    return alerts, reports


def send_mail(config, subject, body):
    smtp = config['smtp']
    username = smtp.get('username', '')
    password = None
    if username:
        if smtp['security'] not in ('ssl', 'starttls'):
            raise ValueError('SMTP authentication requires ssl or starttls')
        if smtp.get('password_file'):
            password = Path(smtp['password_file']).read_text().rstrip('\r\n')
        else:
            password = os.environ.get('SMTP_PASSWORD')
        if not password:
            raise ValueError('Set smtp.password_file or SMTP_PASSWORD for SMTP authentication')
    message = EmailMessage()
    message['From'] = smtp['from']
    message['To'] = ', '.join(smtp['to'])
    message['Subject'] = subject
    message.set_content(body)
    context = ssl.create_default_context()
    mode = smtp['security']
    if mode == 'ssl':
        client = smtplib.SMTP_SSL(smtp['host'], smtp['port'], timeout=30, context=context)
    elif mode in ('starttls', 'none'):
        client = smtplib.SMTP(smtp['host'], smtp['port'], timeout=30)
    else:
        raise ValueError('smtp.security must be ssl, starttls, or none')
    with client:
        if mode == 'starttls':
            client.ehlo()
            client.starttls(context=context)
            client.ehlo()
        if username:
            client.login(username, password)
        refused = client.send_message(message)
        if refused:
            raise RuntimeError(f'SMTP refused recipients: {list(refused)}')
    LOG.info('SMTP accepted the message')


def load_state(path):
    try:
        state = json.loads(path.read_text())
        last = float(state['last_alert'])
        return last
    except FileNotFoundError:
        return 0.0
    except (ValueError, KeyError, TypeError):
        LOG.warning('Invalid state file; alerts will be sent again')
        return 0.0


def save_state(path, timestamp):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps({'last_alert': timestamp}))
    temporary.replace(path)


def run_cycle(config, dry_run=False, once=False):
    alerts, reports = scan(config)
    if STOP.is_set():
        return 0
    if dry_run:
        print('\n\n'.join(reports or alerts))
        return 1 if alerts else 0
    state_path = Path(config['state_file'])
    last_alert = load_state(state_path)
    now = datetime.now(timezone.utc).timestamp()
    if alerts:
        if once or now - last_alert >= config['repeat_hours'] * 3600 or last_alert > now:
            send_mail(config, 'TLS certificates: action required',
                      f'Checked at {datetime.now(timezone.utc).isoformat()}\n\n' + '\n\n'.join(alerts))
            # Persist only after successful SMTP acceptance; failures retry next cycle.
            save_state(state_path, now)
    elif last_alert:
        send_mail(config, 'TLS certificates: recovered',
                  'All configured endpoints were checked successfully and their certificate expiry dates are outside the warning threshold.')
        save_state(state_path, 0)
    return 1 if alerts else 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', default='/etc/cert-monitor/config.json')
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--dry-run', action='store_true')
    modes.add_argument('--once', action='store_true')
    modes.add_argument('--test-mail', action='store_true')
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    config = json.loads(Path(args.config).read_text())
    for name in ('warning_days', 'timeout_seconds', 'check_interval_seconds', 'repeat_hours'):
        if not isinstance(config[name], (int, float)) or config[name] <= 0:
            raise ValueError(f'{name} must be positive')
    if not isinstance(config['smtp']['to'], list) or not config['smtp']['to']:
        raise ValueError('smtp.to must be a non-empty list')
    if args.test_mail:
        send_mail(config, 'TLS certificates: test', 'Test email from certificate monitor.')
        return 0
    if args.dry_run or args.once:
        return run_cycle(config, dry_run=args.dry_run, once=args.once)
    signal.signal(signal.SIGTERM, lambda *_: STOP.set())
    signal.signal(signal.SIGINT, lambda *_: STOP.set())
    while not STOP.is_set():
        try:
            run_cycle(config)
        except Exception:
            LOG.exception('Cycle failed; retrying at next interval')
        STOP.wait(config['check_interval_seconds'])
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
