# SPDX-License-Identifier: Apache-2.0
"""Keep coordinated installation on one fixed local entry and reject partial payloads."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class InstallerEntry(unittest.TestCase):
    def run_entry(self, products):
        with tempfile.TemporaryDirectory(prefix="hrc package with spaces ") as folder:
            package = Path(folder)
            (package / "Tools").mkdir()
            (package / "Bin").mkdir()
            shutil.copyfile(ROOT / "Tools/Install.sh", package / "Tools/Install.sh")
            binary = package / "Bin/hrc"
            binary.write_text("#!/usr/bin/python3\nimport json,sys\nprint(json.dumps(sys.argv[1:]))\n")
            binary.chmod(0o700)
            for product in products:
                (package / "Packages" / product).mkdir(parents=True)
            result = subprocess.run(["/bin/bash", str(package / "Tools/Install.sh")],
                                    cwd="/", capture_output=True, text=True, timeout=5,
                                    env={"PATH": os.defpath})
            return result, str(package / "Packages")

    def test_coordinated_payload_uses_one_exact_folder_argument(self):
        result, packages = self.run_entry(["Core", "Suite"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), ["install", "--native-packages", packages])

    def test_legacy_package_retains_launcher_only_installation(self):
        result, _ = self.run_entry([])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), ["install"])

    def test_partial_coordinated_payload_never_starts_the_installer(self):
        for product in ["Core", "Suite"]:
            with self.subTest(product=product):
                result, _ = self.run_entry([product])
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
                self.assertIn("incomplete", result.stderr)


if __name__ == "__main__":
    unittest.main()
