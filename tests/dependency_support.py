"""Skip only integrations whose executable/field requirements are unmet."""
import shutil
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"live"))
import unittest

def require_command(name):
    if not shutil.which(name):
        raise unittest.SkipTest(f'{name} not installed: external integration not executed')

def require_tshark(command):
    from dependencies import require_fields
    require_command('tshark')
    required=[command[i+1] for i,x in enumerate(command[:-1]) if x=='-e']
    try:
        require_fields(required)
    except RuntimeError as exc:
        raise unittest.SkipTest(str(exc)) from exc
