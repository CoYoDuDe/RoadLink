"""Durable file-change journal for a single controller.

No network operation is implemented here. A controller must hold its process
lock, start an independent watchdog, and apply/revert runtime state separately.
An unconfirmed journal is recoverable after process failure or reboot.
"""
import base64
import hashlib
import os
from pathlib import Path
import secrets
import stat
import time

from storage import atomic_write, load_json, write_json


def digest(data):
    return None if data is None else hashlib.sha256(data).hexdigest()


class Journal:
    def __init__(self, state_dir, allowed_files):
        self.root = Path(state_dir)
        self.path = self.root / 'pending.json'
        self.allowed = {str(Path(p).absolute()) for p in allowed_files}

    def _target(self, value):
        path = Path(value).absolute()
        if str(path) not in self.allowed:
            raise ValueError('File is outside the network transaction allowlist')
        if any(p.is_symlink() for p in (path, *path.parents)):
            raise ValueError('Symlink targets are not permitted')
        if path.exists() and not path.is_file():
            raise ValueError('Only regular files can be journalled')
        return path

    def begin(self, updates, boot_id, timeout=90):
        if self.path.exists():
            raise RuntimeError('An unconfirmed transaction already exists')
        if not 10 <= timeout <= 300 or not updates:
            raise ValueError('Invalid rollback timeout or empty update')
        records = []
        for name, data in updates.items():
            if not isinstance(data, bytes) or len(data) > 1048576:
                raise ValueError('Configuration must be bytes and at most 1 MiB')
            path = self._target(name)
            before = path.read_bytes() if path.exists() else None
            records.append({'path': str(path),
                'before': None if before is None else base64.b64encode(before).decode(),
                'before_hash': digest(before), 'after_hash': digest(data),
                'after': base64.b64encode(data).decode(),
                'mode': stat.S_IMODE(path.stat().st_mode) if before is not None else 0o600})
        transaction = {'id': secrets.token_hex(16), 'boot_id': boot_id,
            'deadline': time.time() + timeout, 'phase': 'prepared', 'files': records}
        write_json(self.path, transaction)  # Durably precedes every system mutation.
        return transaction['id']

    def apply(self, transaction_id):
        transaction = self._get(transaction_id)
        for record in transaction['files']:
            path = self._target(record['path'])
            current = path.read_bytes() if path.exists() else None
            if digest(current) not in (record['before_hash'], record['after_hash']):
                raise RuntimeError('Configuration changed concurrently: ' + str(path))
            atomic_write(path, base64.b64decode(record['after']), record['mode'])
        transaction['phase'] = 'applied'
        write_json(self.path, transaction)

    def confirm(self, transaction_id, boot_id, healthy):
        transaction = self._get(transaction_id)
        if not healthy or transaction['phase'] != 'applied':
            raise RuntimeError('A verified applied transaction is required')
        if transaction['boot_id'] != boot_id or time.time() >= transaction['deadline']:
            raise RuntimeError('Confirmation deadline expired or system rebooted')
        for record in transaction['files']:
            path = self._target(record['path'])
            if not path.exists() or digest(path.read_bytes()) != record['after_hash']:
                raise RuntimeError('Applied configuration no longer matches')
        # Commit before unlink: a crash between these steps must never undo a confirmed change.
        transaction['phase'] = 'committed'
        write_json(self.path, transaction)
        self.path.unlink()

    def rollback(self, transaction_id=None):
        transaction = self._get(transaction_id)
        if transaction['phase'] == 'committed':
            self.path.unlink()
            return
        for record in reversed(transaction['files']):
            path = self._target(record['path'])
            current = path.read_bytes() if path.exists() else None
            current_hash = digest(current)
            if current_hash == record['before_hash']:
                continue
            if current_hash != record['after_hash']:
                raise RuntimeError('Rollback conflict; preserving third-party edit: ' + str(path))
            if record['before'] is None:
                path.unlink()
            else:
                atomic_write(path, base64.b64decode(record['before']), record['mode'])
        self.path.unlink()

    def needs_recovery(self, boot_id, now=None):
        transaction = load_json(self.path)
        if not transaction:
            return False
        if transaction['phase'] == 'committed':
            self.path.unlink()
            return False
        return transaction['boot_id'] != boot_id or (time.time() if now is None else now) >= transaction['deadline']

    def _get(self, transaction_id):
        transaction = load_json(self.path)
        if not transaction or (transaction_id is not None and transaction_id != transaction['id']):
            raise RuntimeError('No matching pending transaction')
        return transaction
