#!/usr/bin/env python3
"""Check full GUI dissection fields before asking for radio permissions."""
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'live')]
from engine import FIELDS
from discovery import EXTRA_FIELDS
from dependencies import require_fields
try:
    require_fields(FIELDS+EXTRA_FIELDS)
except RuntimeError as exc:
    raise SystemExit(str(exc))
print('TShark: all required GUI dissection fields available.')
