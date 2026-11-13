# SPDX-License-Identifier: Apache-2.0
"""Check release build flags and refusal before binary execution or archive creation."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "Tools"))
import Package


class PackagePaths(unittest.TestCase):
    def test_encoded_flags_preserve_spaces_and_take_precedence(self):
        environment = {
            "HOME": "/private/Build User",
            "CARGO_HOME": "/cache/Cargo Files",
            "CARGO_TARGET_DIR": "/private/Build User/Shared Target",
            "CARGO_ENCODED_RUSTFLAGS": "-C\x1flink-arg=/library path/input.a",
            "RUSTFLAGS": "--unused-fallback",
        }
        with patch.dict(os.environ, environment, clear=True), patch.object(
                Package, "ROOT", Path("/private/Build User/Chat Source")):
            flags = Package.build_rustflags().split("\x1f")
        self.assertEqual(flags[:2], ["-C", "link-arg=/library path/input.a"])
        self.assertNotIn("--unused-fallback", flags)
        self.assertEqual(flags[-1], "--remap-path-prefix=/private/Build User/Chat Source=/source")
        self.assertIn("--remap-path-prefix=/private/Build User=/build", flags)
        self.assertIn("--remap-path-prefix=/cache/Cargo Files=/cargo", flags)
        self.assertIn("--remap-path-prefix=/private/Build User/Shared Target=/target", flags)

    def test_plain_flags_and_unrepresentable_path(self):
        with patch.dict(os.environ, {"HOME": "/private/build", "RUSTFLAGS": "-C  opt-level=2\t--cfg test_build"}, clear=True):
            self.assertEqual(Package.build_rustflags().split("\x1f")[:4],
                             ["-C", "opt-level=2", "--cfg", "test_build"])
        with patch.dict(os.environ, {"HOME": "/private/bad\x1fpath"}, clear=True):
            with self.assertRaisesRegex(SystemExit, "cannot be represented safely"):
                Package.build_rustflags()

    def test_known_paths_are_refused_and_remapped_bytes_are_allowed(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(
                Package, "build_remaps", return_value=[
                    ("/private/home", "/build"),
                    ("/private/cache", "/cargo"),
                    ("/private/source", "/source"),
                    ("/private/target", "/target"),
                ]):
            binary = Path(temporary) / "binary"
            for prefix in (b"/private/home", b"/private/cache", b"/private/source", b"/private/target"):
                binary.write_bytes(b"\x7fELF\0" + prefix + b"/input.rs\0")
                with self.assertRaises(SystemExit) as result:
                    Package.verify_build_paths(binary)
                self.assertNotIn("/private/", str(result.exception))
            binary.write_bytes(b"\x7fELF\0/build/input.rs\0/cargo/library.rs\0/source/main.rs\0")
            Package.verify_build_paths(binary)

    def test_cli_refuses_before_execution_and_creates_no_archive(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            binary = directory / "not-executable"
            binary.write_bytes(b"\x7fELF\0" + os.fsencode(ROOT) + b"/Source/Main.rs\0")
            output = directory / "package.tar.gz"
            result = subprocess.run([
                sys.executable, "-B", str(ROOT / "Tools/Package.py"),
                "--binary", str(binary), "--sqlcipher-source", str(directory),
                "--output", str(output),
            ], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "")
            self.assertEqual(result.stderr.strip(),
                             "Binary retains private build paths; rebuild with package path remapping")
            self.assertFalse(output.exists())

    def test_native_loader_contract_checks_real_elf_dependencies(self):
        self.assertIn("libc.so.6", Package.runtime_dependencies(Path("/usr/bin/true")))
        with self.assertRaisesRegex(SystemExit, "outside the native hosting runtime"):
            Package.runtime_dependencies(Path("/usr/bin/openssl"))

    def test_cli_refuses_dynamic_crypto_before_executing_the_binary(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            output = directory / "package.tar.gz"
            result = subprocess.run([
                sys.executable, "-B", str(ROOT / "Tools/Package.py"),
                "--binary", "/usr/bin/openssl", "--sqlcipher-source", str(directory),
                "--output", str(output),
            ], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "")
            self.assertEqual(result.stderr.strip(),
                             "Binary requires shared libraries outside the native hosting runtime; "
                             "rebuild with Tools/Environment.sh and static OpenSSL")
            self.assertFalse(output.exists())

    def test_environment_requires_major_three_with_real_pkg_config(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            library = directory / "lib"
            library.mkdir()
            for name in ["libcrypto.a", "libsqlcipher.a"]:
                (library / name).write_bytes(b"fixture archive presence")
            environment = dict(os.environ, PKG_CONFIG_PATH=str(directory),
                               PKG_CONFIG_LIBDIR=str(directory), HRC_NATIVE_PREFIX=str(directory))
            for version, accepted in [("3.0.13", True), ("4.0.0", False), ("1.1.1", False)]:
                (directory / "libcrypto.pc").write_text(
                    f"libdir={library}\nName: OpenSSL-libcrypto\nDescription: Version boundary fixture\n"
                    f"Version: {version}\nLibs: -L${{libdir}} -lcrypto\n")
                result = subprocess.run([
                    "bash", "-ec", 'source "$1"; test "$HRC_CRYPTO_LIB_DIR" = "$2"',
                    "environment-check", str(ROOT / "Tools/Environment.sh"), str(library),
                ], env=environment, capture_output=True, text=True)
                self.assertEqual(result.returncode == 0, accepted, result.stderr)
                if not accepted:
                    self.assertIn("Install the OpenSSL 3 development package", result.stderr)


if __name__ == "__main__":
    unittest.main()
