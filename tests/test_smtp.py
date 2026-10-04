import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch
import monitor

class SMTPTests(unittest.TestCase):
    def config(self, mode='ssl', **extra):
        return {'smtp': dict(host='smtp.example.com', port=465, security=mode,
                             **{'from': 'a@example.com', 'to': ['b@example.com']}, **extra)}

    @patch.dict(os.environ, {}, clear=True)
    def test_no_auth_all_transports(self):
        for mode in ('none', 'ssl', 'starttls'):
            with self.subTest(mode=mode), patch('monitor.smtplib.SMTP') as plain, patch('monitor.smtplib.SMTP_SSL') as secure:
                client = (secure if mode == 'ssl' else plain).return_value.__enter__.return_value
                client.send_message.return_value = {}
                monitor.send_mail(self.config(mode), 'Test', 'Body')
                client.login.assert_not_called()
                client.send_message.assert_called_once()

    @patch.dict(os.environ, {'SMTP_PASSWORD': 'environment-password'}, clear=True)
    def test_auth_and_starttls_order(self):
        with patch('monitor.smtplib.SMTP') as smtp:
            client = smtp.return_value.__enter__.return_value
            client.send_message.return_value = {}
            monitor.send_mail(self.config('starttls', username='user'), 'Test', 'Body')
            names = [call[0] for call in client.method_calls]
            self.assertLess(names.index('starttls'), names.index('login'))
            self.assertLess(names.index('login'), names.index('send_message'))
            client.login.assert_called_once_with('user', 'environment-password')

    @patch.dict(os.environ, {'SMTP_PASSWORD': 'ignored'}, clear=True)
    def test_secret_file_precedence(self):
        with tempfile.TemporaryDirectory() as folder, patch('monitor.smtplib.SMTP_SSL') as smtp:
            secret = Path(folder) / 'password'
            secret.write_text('secret with spaces \n')
            client = smtp.return_value.__enter__.return_value
            client.send_message.return_value = {}
            monitor.send_mail(self.config(username='user', password_file=str(secret)), 'Test', 'Body')
            client.login.assert_called_once_with('user', 'secret with spaces ')

    @patch.dict(os.environ, {}, clear=True)
    def test_missing_password_and_plaintext_rejected(self):
        with patch('monitor.smtplib.SMTP_SSL') as smtp:
            with self.assertRaises(ValueError):
                monitor.send_mail(self.config(username='user'), 'Test', 'Body')
            smtp.assert_not_called()
        with self.assertRaises(ValueError):
            monitor.send_mail(self.config('none', username='user'), 'Test', 'Body')

    @patch.dict(os.environ, {'SMTP_PASSWORD': 'wrong'}, clear=True)
    def test_failed_login_never_sends(self):
        with patch('monitor.smtplib.SMTP_SSL') as smtp:
            client = smtp.return_value.__enter__.return_value
            client.login.side_effect = monitor.smtplib.SMTPAuthenticationError(535, b'Failed')
            with self.assertRaises(monitor.smtplib.SMTPAuthenticationError):
                monitor.send_mail(self.config(username='user'), 'Test', 'Body')
            client.send_message.assert_not_called()
