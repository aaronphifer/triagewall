import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from triagewall.lab.store import LabStore


class LabStoreInitializationTests(unittest.TestCase):
    def test_separate_ui_and_worker_initialization_is_idempotent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "lab-data"
            LabStore(root).initialize()
            LabStore(root).initialize()

            self.assertEqual(
                {path.name for path in root.iterdir()},
                set(LabStore._KINDS),
            )

    def test_concurrent_ui_and_worker_initialization_is_safe(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "lab-data"

            def initialize(_index):
                LabStore(root).initialize()

            with ThreadPoolExecutor(max_workers=8) as executor:
                list(executor.map(initialize, range(32)))

            self.assertTrue(all((root / name).is_dir() for name in LabStore._KINDS))


if __name__ == "__main__":
    unittest.main()
