import contextlib
import io
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

from scripts import generate_lab_api_key


class GenerateLabApiKeyTests(unittest.TestCase):
    def test_credentials_are_written_privately_without_logging_secrets(self):
        with tempfile.TemporaryDirectory() as tmp:
            output_path = Path(tmp) / "credentials.txt"
            stdout = io.StringIO()
            generated = [
                "operator-access-secret-1234567890",
                "session-signing-secret-1234567890",
            ]
            with mock.patch.object(
                generate_lab_api_key.secrets,
                "token_urlsafe",
                side_effect=generated,
            ), contextlib.redirect_stdout(stdout):
                self.assertEqual(
                    generate_lab_api_key.main(["--output", str(output_path)]),
                    0,
                )

            contents = output_path.read_text(encoding="utf-8")
            self.assertIn(
                "TRIAGEWALL_LAB_ACCESS_KEY='operator-access-secret-1234567890'",
                contents,
            )
            self.assertIn("TRIAGEWALL_LAB_API_KEY_HASH='pbkdf2_sha256$", contents)
            self.assertIn(
                "TRIAGEWALL_LAB_SESSION_SECRET='session-signing-secret-1234567890'",
                contents,
            )
            self.assertNotIn("operator-access-secret-1234567890", stdout.getvalue())
            self.assertNotIn("session-signing-secret-1234567890", stdout.getvalue())
            if os.name != "nt":
                self.assertEqual(
                    stat.S_IMODE(output_path.stat().st_mode),
                    stat.S_IRUSR | stat.S_IWUSR,
                )

    def test_existing_file_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            output_path = Path(tmp) / "credentials.txt"
            output_path.write_text("keep-me", encoding="utf-8")
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    generate_lab_api_key.main(["--output", str(output_path)])
            self.assertEqual(output_path.read_text(encoding="utf-8"), "keep-me")


if __name__ == "__main__":
    unittest.main()
