"""Offline regression checks; synthetic examples only."""
import tempfile
import unittest
from pathlib import Path

from scripts.security_scan import inspect_file


class SecurityScanTests(unittest.TestCase):
    def check(self, name: str, contents: bytes):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(contents)
            return inspect_file(root, name)

    def test_safe_text(self):
        self.assertEqual(self.check("README.md", b"Public documentation"), [])

    def test_example_env_is_allowed(self):
        self.assertEqual(self.check(".env.example", b"KEY=replace-me"), [])

    def test_private_env_is_rejected(self):
        self.assertIn("environment secrets file", self.check(".env", b"KEY=placeholder"))

    def test_key_file_is_rejected(self):
        self.assertIn("sensitive or opaque file extension", self.check("certs/key.pem", b"placeholder"))

    def test_archive_is_rejected(self):
        self.assertIn("sensitive or opaque file extension", self.check("code.zip", b"placeholder"))

    def test_token_pattern_is_rejected(self):
        token = b"ghp_" + b"A" * 36
        self.assertIn("possible GitHub classic token", self.check("config.txt", token))

    def test_traversal_is_rejected(self):
        self.assertEqual(inspect_file(Path("."), "../outside"), ["unsafe path"])


if __name__ == "__main__":
    unittest.main()
