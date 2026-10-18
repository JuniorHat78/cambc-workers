import contextlib
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from cryptography.exceptions import InvalidTag
import sealed
import worker


class Contracts(unittest.TestCase):
    def test_roundtrip_and_tampering(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / 'source'
            source.write_bytes(b'private workload canary\0' * 1000)
            key = os.urandom(32)
            box = root / 'input.box'
            sealed.seal(source, box, key)
            self.assertNotIn(b'private workload canary', box.read_bytes())
            sealed.unseal(box, root / 'recovered', key)
            self.assertEqual(source.read_bytes(), (root / 'recovered').read_bytes())
            data = bytearray(box.read_bytes())
            data[-17] ^= 1
            box.write_bytes(data)
            with self.assertRaises(InvalidTag):
                sealed.unseal(box, root / 'corrupt', key)
            self.assertFalse((root / 'corrupt').exists())
            self.assertFalse((root / 'corrupt.partial').exists())

    def test_wrong_key(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'a').write_bytes(b'payload')
            sealed.seal(root / 'a', root / 'b', os.urandom(32))
            with self.assertRaises(InvalidTag):
                sealed.unseal(root / 'b', root / 'c', os.urandom(32))

    def test_archive_inventory(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / 'src'
            source.mkdir()
            (source / 'entry.py').write_text('pass')
            sealed.pack_checked(source, root / 'a.tar.gz', {'entry': 'entry.py'})
            self.assertEqual(sealed.extract_checked(root / 'a.tar.gz', root / 'dest')['entry'], 'entry.py')
            (source / 'entry.py').write_text('changed')
            with tarfile.open(root / 'bad.tar.gz', 'w:gz') as tar:
                for p in source.iterdir():
                    tar.add(p, arcname=p.name)
            with self.assertRaisesRegex(ValueError, 'digest'):
                sealed.extract_checked(root / 'bad.tar.gz', root / 'bad')

    def test_unsafe_archives(self):
        for name, kind in [('../escape', tarfile.REGTYPE), ('/escape', tarfile.REGTYPE),
                           ('x\\escape', tarfile.REGTYPE), ('C:escape', tarfile.REGTYPE),
                           ('link', tarfile.SYMTYPE), ('hard', tarfile.LNKTYPE)]:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                with tarfile.open(root / 'bad.tar.gz', 'w:gz') as tar:
                    item = tarfile.TarInfo(name)
                    item.type = kind
                    item.linkname = '../escape'
                    tar.addfile(item, io.BytesIO())
                with self.assertRaisesRegex(ValueError, 'Unsafe'):
                    sealed.extract_checked(root / 'bad.tar.gz', root / 'out')

    def test_environment_contains_no_provider_credentials(self):
        with patch.dict(os.environ, {'BOX_KEY': 'canary', 'GH_TOKEN': 'canary',
                'GITHUB_TOKEN': 'canary', 'UNEXPECTED_SECRET': 'canary', 'PATH': 'bin'}):
            env = worker.child_environment('private-home')
            self.assertNotIn('canary', env.values())
            self.assertEqual(env['PATH'], 'bin')

    def test_private_stdout_and_stderr(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output = root / 'output'
            output.mkdir()
            script = root / 'entry.py'
            script.write_text("import sys; print('private canary'); print('private error', file=sys.stderr); raise ValueError('private exception')")
            captured = io.StringIO()
            with contextlib.redirect_stdout(captured):
                code = worker.execute(script, root, output, 0, worker.child_environment(root), 20)
            self.assertNotEqual(code, 0)
            self.assertEqual(captured.getvalue(), '')
            self.assertIn('private exception', (output / 'execution.log').read_text())


if __name__ == '__main__':
    unittest.main()
