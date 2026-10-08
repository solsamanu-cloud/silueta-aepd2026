"""Lectura paginada del registro completo, también mientras se está escribiendo."""
import json
from pathlib import Path
import re


def read_history(root, session, cursor=0, limit=4000):
    if not isinstance(session, str) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}', session):
        raise ValueError('Sesión no válida')
    cursor, limit = int(cursor), int(limit)
    if cursor < 0 or not 1 <= limit <= 4000:
        raise ValueError('Página no válida')
    root = Path(root).resolve()
    folder = (root / session).resolve()
    if folder.parent != root:
        raise ValueError('Sesión fuera del archivo')
    source = folder / 'variance.jsonl'
    if source.is_symlink():
        raise ValueError('Registro no válido')
    points = []
    with source.open('rb') as stream:
        stream.seek(0, 2)
        end = stream.tell()
        if cursor > end:
            raise ValueError('Cursor fuera del registro')
        if cursor:
            stream.seek(cursor - 1)
            if stream.read(1) != b'\n':
                raise ValueError('Cursor fuera del límite de una muestra')
        stream.seek(cursor)
        while len(points) < limit and stream.tell() < end:
            start = stream.tell()
            line = stream.readline(end - start)
            if not line.endswith(b'\n'):
                stream.seek(start)  # La siguiente petición recogerá la escritura completa.
                break
            points.append(json.loads(line))
        next_cursor = stream.tell()
    return {'session': session, 'points': points, 'next_cursor': next_cursor,
            'eof': len(points) < limit or next_cursor >= end}
