# SPDX-License-Identifier: Apache-2.0
"""The existing package inventory includes exact signed inputs, never adjacent private files."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "Tools"))
import Package


class CoordinatedPayload(unittest.TestCase):
    def prepare(self, directory):
        for label, product in [("Core", "HyperNet"), ("Suite", "HyperNetSuite")]:
            folder = directory / label
            folder.mkdir()
            for suffix in [".tar", ".tar.sig", ".target.json", ".target.json.sig"]:
                (folder / (product + "-0.11.0-linux-x86_64" + suffix)).write_bytes(b"fixture")
            (folder / "Publisher.pub").write_bytes(b"fixture public key")
            (folder / "Unrelated.key").write_bytes(b"synthetic excluded fixture")

    def verified(self, *args):
        if args[1:] == ("manage", "capabilities"):
            return json.dumps({"nativePackages": {"core": "0.11.0", "suite": "0.11.0"}})
        product = {"core": "HyperNet", "suite": "HyperNetSuite"}[args[5]]
        return json.dumps({"status": "VerifiedArchive", "product": product, "version": "0.11.0"})

    def test_only_exact_supported_sets_enter_the_existing_inventory(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.prepare(root)
            with patch.object(Package, "command", side_effect=self.verified) as command:
                files, metadata = Package.native_files(root, Path("/verified/hrc"))
            self.assertEqual(len(files), 10)
            self.assertFalse(any("Unrelated" in name for name in files))
            self.assertEqual(metadata["suite"]["directory"], "Packages/Suite")
            self.assertEqual(command.call_count, 3)
            (root / "Suite/Publisher.pub").unlink()
            with patch.object(Package, "command", side_effect=self.verified):
                with self.assertRaises(FileNotFoundError):
                    Package.native_files(root, Path("/verified/hrc"))

    def test_symlinked_or_unverified_payload_is_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.prepare(root)
            archive = root / "Core/HyperNet-0.11.0-linux-x86_64.tar"
            archive.unlink()
            archive.symlink_to("Unrelated.key")
            with patch.object(Package, "command", side_effect=self.verified):
                with self.assertRaisesRegex(ValueError, "regular file"):
                    Package.native_files(root, Path("/verified/hrc"))
            archive.unlink()
            archive.write_bytes(b"fixture")
            with patch.object(Package, "command", side_effect=[self.verified("hrc", "manage", "capabilities"), "{}"]):
                with self.assertRaisesRegex(ValueError, "did not confirm"):
                    Package.native_files(root, Path("/verified/hrc"))


if __name__ == "__main__":
    unittest.main()
