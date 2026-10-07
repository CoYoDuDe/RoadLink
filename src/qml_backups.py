"""Repair only exact, proven old RoadLink files promoted to native originals."""
import hashlib
import json
import os
from pathlib import Path
import shutil


def repair():
    known = json.loads(Path(__file__).with_suffix('.json').read_text(encoding='utf-8'))
    folder = Path('/opt/victronenergy/gui/qml')
    backups = Path('/data/setupOptions/RoadLink/qml-backup-repair')
    for name, hashes in known.items():
        original = folder / (name + '.orig')
        if not original.is_file() or original.is_symlink():
            continue
        digest = hashlib.sha256(original.read_bytes()).hexdigest()
        if digest not in hashes:
            continue
        backups.mkdir(mode=0o700, parents=True, exist_ok=True)
        saved = backups / (name + '.' + digest)
        if not saved.exists():
            shutil.copyfile(original, saved)
            os.chmod(saved, 0o600)
        if hashlib.sha256(saved.read_bytes()).hexdigest() != digest:
            raise RuntimeError('Cannot preserve known RoadLink backup')
        if hashlib.sha256(original.read_bytes()).hexdigest() != digest:
            raise RuntimeError('GUI backup changed during repair')
        marker = folder / (name + '.NO_ORIG')
        marker.touch()
        original.unlink()


if __name__ == '__main__':
    repair()
