#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Collect locked Rust and SQLCipher notices; refuse unaccounted dependency licences."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tomllib

ROOT = Path(__file__).resolve().parent.parent
SQLCIPHER_COMMIT = "355d4db92d3404e71faa8088d071a71d767807f4"
NAMES = ("license", "licence", "copying", "notice", "copyright")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def notices(sqlcipher):
    metadata = json.loads(subprocess.check_output([
        "cargo", "metadata", "--locked", "--offline", "--format-version", "1",
        "--filter-platform", "x86_64-unknown-linux-gnu",
    ], cwd=ROOT, text=True))
    sources = json.loads((ROOT / "Packaging/NoticeSources.json").read_text())
    text = ["Third-party notices for HyperNet Relay Chat\n",
            "Cargo.lock SHA-256: " + digest(ROOT / "Cargo.lock") + "\n",
            "Includes the Linux dependency resolution, including build dependencies.\n"
            "Declarations do not replace the accompanying licence terms.\n"]
    packages = []
    covered_sources = {}
    locked = {(p["name"], p["version"]): p for p in
              tomllib.loads((ROOT / "Cargo.lock").read_text())["package"]}
    for package in sorted(metadata["packages"], key=lambda p: (p["name"], p["version"])):
        if package["source"] is None:
            continue
        name = package["name"] + "@" + package["version"]
        directory = Path(package["manifest_path"]).parent
        files = sorted(p for p in directory.rglob("*")
                       if p.is_file() and not p.is_symlink()
                       and any(n in p.name.lower() for n in NAMES))
        records = []
        for path in files:
            if path.stat().st_size > 1024 * 1024:
                raise ValueError("Oversized dependency notice: " + name)
            records.append((str(path.relative_to(directory)), path.read_text()))
        for source in sources.get(name, []):
            path = ROOT / "Packaging/Notices" / source["file"]
            if path.parent != ROOT / "Packaging/Notices" or digest(path) != source["sha256"]:
                raise ValueError("Changed upstream notice: " + name)
            records.append((source["source"], path.read_text()))
        if not package["license"] or not records:
            raise ValueError("Missing dependency licence or notice: " + name)
        text.extend(["\n" + "=" * 72 + "\n", name + "\n",
                     "Declared licence: " + package["license"] + "\n",
                     "Source: https://static.crates.io/crates/" + package["name"] + "/"
                     + package["name"] + "-" + package["version"] + ".crate\n"])
        for label, content in records:
            text.extend(["\n" + label + "\n", content + "\n"])
        source_archive = ("https://static.crates.io/crates/" + package["name"] + "/"
                          + package["name"] + "-" + package["version"] + ".crate")
        packages.append({"name": package["name"], "version": package["version"],
                         "license": package["license"], "sourceArchive": source_archive,
                         "archiveSha256": locked[(package["name"], package["version"])]["checksum"]})
        if "MPL-2.0" in package["license"]:
            source_prefix = "ThirdPartySources/" + package["name"] + "-" + package["version"]
            packages[-1]["includedSource"] = source_prefix
            text.append("\nSource is also included at " + source_prefix + ".\n")
            for path in sorted(directory.rglob("*")):
                if path.is_symlink():
                    raise ValueError("Unexpected dependency source symlink: " + name)
                if path.is_file() and path.name != ".cargo-ok":
                    covered_sources[source_prefix + "/" + str(path.relative_to(directory))] = path
    revision = subprocess.check_output([
        "git", "-C", str(sqlcipher), "rev-parse", "HEAD"], text=True).strip()
    if revision != SQLCIPHER_COMMIT:
        raise ValueError("SQLCipher source revision differs from the controlled engine")
    for filename in ("LICENSE.txt", "LICENSE.md"):
        path = sqlcipher / filename
        text.extend(["\n" + "=" * 72 + "\nSQLCipher " + SQLCIPHER_COMMIT + "\n",
                     filename + "\n", path.read_text() + "\n"])
    return "".join(text), packages, covered_sources


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sqlcipher-source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    content, _, _ = notices(args.sqlcipher_source.resolve(strict=True))
    with args.output.open("x") as output:
        output.write(content)


if __name__ == "__main__":
    main()
