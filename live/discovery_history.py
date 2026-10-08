"""Catálogo acumulado y resultados de cada barrido, conservados entre reinicios."""
from copy import deepcopy
import json
from pathlib import Path
import uuid


class DiscoveryHistory:
    def __init__(self, path=None):
        self.path = Path(path) if path else None
        self.catalog = {}
        self.scans = []
        self.error = None
        if self.path and self.path.exists():
            try:
                saved = json.loads(self.path.read_text())
                if saved.get('schema') != 1 or not isinstance(saved['catalog'], dict) or not isinstance(saved['scans'], list):
                    raise ValueError('formato no reconocido')
                self.catalog, self.scans = saved['catalog'], saved['scans']
            except (OSError, ValueError, KeyError, TypeError) as exc:
                # Un archivo ilegible nunca se reemplaza silenciosamente por uno vacío.
                self.error = 'No se pudo leer el histórico: ' + str(exc)

    @property
    def current(self):
        return self.scans[-1] if self.scans else None

    def begin(self, started):
        self.scans.append(dict(id=uuid.uuid4().hex, started=started, ended=None,
                               status='scanning', clients=[], channel_index=0,
                               channel_total=0, skipped=[], error=None))

    def update(self, observed=None, **progress):
        scan = self.current
        if not scan:
            return
        for key in ('channel_index', 'channel_total', 'skipped', 'error'):
            if key in progress:
                scan[key] = deepcopy(progress[key])
        if observed is not None:
            scan['clients'] = deepcopy(observed)
            for peer in observed:
                key = peer['key']
                old = self.catalog.get(key, {})
                self.catalog[key] = {**deepcopy(old), **deepcopy(peer),
                    'first_seen': old.get('first_seen', peer.get('last_seen')),
                    'last_scan': scan['id'],
                    'seen_scans': old.get('seen_scans', 0) + (old.get('last_scan') != scan['id'])}
        if progress.get('scanning') is False:
            scan['ended'] = progress['ended']
            scan['status'] = 'error' if scan.get('error') else 'cancelled' if progress.get('cancelled') else 'complete'
        self.save()

    def save(self):
        if not self.path or self.error:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp = self.path.with_suffix('.tmp')
        temp.write_text(json.dumps(dict(schema=1, catalog=self.catalog, scans=self.scans),
                                   ensure_ascii=False, allow_nan=False), encoding='utf-8')
        temp.replace(self.path)

    def snapshot(self):
        current = self.current
        scan_id = current['id'] if current else None
        peers = [{**deepcopy(p), 'seen_in_latest_scan': p.get('last_scan') == scan_id}
                 for p in self.catalog.values()]
        peers.sort(key=lambda p: (not p['seen_in_latest_scan'], -p.get('compatible_bfi', 0),
                                 p.get('id') or 'Z', p['key']))
        return dict(clients=peers, scans=deepcopy(self.scans), history_error=self.error,
                    current_scan_id=scan_id,
                    current_count=len(current['clients']) if current else 0)
