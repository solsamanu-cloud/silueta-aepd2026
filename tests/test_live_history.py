import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'live'))
from history import read_history


class HistoryTests(unittest.TestCase):
    def test_full_history_beyond_memory_limit_and_live_append(self):
        with tempfile.TemporaryDirectory() as temp:
            folder=Path(temp)/'session-01';folder.mkdir()
            path=folder/'variance.jsonl'
            rows=[{'t':i*1.33, 'variance':None if i<5 else i/100000} for i in range(12037)]
            path.write_text(''.join(json.dumps(p)+'\n' for p in rows))
            got=[];cursor=0
            while True:
                page=read_history(temp,'session-01',cursor)
                got.extend(page['points']);cursor=page['next_cursor']
                if page['eof']:break
            self.assertEqual(got,rows)
            extra={'t':16020.,'variance':.01}
            with path.open('a') as f:f.write(json.dumps(extra))
            page=read_history(temp,'session-01',cursor)
            self.assertEqual(page['points'],[])
            self.assertEqual(page['next_cursor'],cursor)
            with path.open('a') as f:f.write('\n')
            self.assertEqual(read_history(temp,'session-01',cursor)['points'],[extra])

    def test_invalid_path_and_cursor(self):
        with tempfile.TemporaryDirectory() as temp:
            folder=Path(temp)/'session';folder.mkdir()
            (folder/'variance.jsonl').write_text('{"t":1}\n')
            for session,cursor in [('../session',0),('session',-1),('session',2),('session',999)]:
                with self.assertRaises(ValueError):read_history(temp,session,cursor)


if __name__=='__main__':unittest.main()
