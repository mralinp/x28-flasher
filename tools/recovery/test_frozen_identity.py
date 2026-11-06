"""Frozen x28-flasher: no venv re-exec, and the XML library identity comes from the bundle (#272)."""
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import common
import restore_entry

TEXT = "class DAXML:\n    pass  # patched\n"


def bundle(commit=common.MTKCLIENT_COMMIT, text=TEXT, recorded=None):
    root = Path(tempfile.mkdtemp())
    (root / restore_entry.XML).parent.mkdir(parents=True)
    (root / restore_entry.XML).write_text(text)
    sha = recorded or hashlib.sha256(TEXT.encode()).hexdigest()
    (root / 'identity.json').write_text(json.dumps({'commit': commit, 'xml_lib_sha256': sha}))
    return root


class FrozenIdentityTests(unittest.TestCase):
    def identity(self, root):
        with mock.patch.object(restore_entry, 'FROZEN', True), mock.patch.object(sys, '_MEIPASS', str(root), create=True):
            return restore_entry.host_identity()

    def test_bundled_library_matching_the_recorded_hash_is_accepted(self):
        self.assertEqual(self.identity(bundle()), TEXT)

    def test_modified_library_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'does not match'):
            self.identity(bundle(text=TEXT + '# tampered\n'))

    def test_other_mtkclient_commit_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'does not match'):
            self.identity(bundle(commit='0' * 40))

    def test_frozen_never_enters_a_venv(self):
        with mock.patch.object(common, 'FROZEN', True), mock.patch.object(common.os, 'execv') as execv:
            common.ensure_venv()
        execv.assert_not_called()

    def test_developer_run_outside_the_venv_reexecs(self):
        with mock.patch.object(common, 'FROZEN', False), mock.patch.object(common.Path, 'exists', return_value=True), \
                mock.patch.object(common.os, 'execv') as execv:
            common.ensure_venv()
        execv.assert_called_once()

    def test_other_venv_on_the_same_interpreter_reexecs(self):
        """Another mtkclient venv shares the base python symlink target; only sys.prefix tells them apart."""
        with mock.patch.object(common, 'FROZEN', False), mock.patch.object(common.Path, 'exists', return_value=True), \
                mock.patch.object(common.sys, 'executable', str(common.MTK_HOME / 'venv' / 'bin' / 'python')), \
                mock.patch.object(common.sys, 'prefix', '/elsewhere/mtkclient/venv'), mock.patch.object(common.os, 'execv') as execv:
            common.ensure_venv()
        execv.assert_called_once()

    def test_pinned_venv_does_not_reexec(self):
        with mock.patch.object(common, 'FROZEN', False), mock.patch.object(common.sys, 'prefix', str(common.MTK_HOME / 'venv')), \
                mock.patch.object(common.os, 'execv') as execv:
            common.ensure_venv()
        execv.assert_not_called()


if __name__ == '__main__':
    unittest.main()
