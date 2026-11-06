#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Assemble one Linux package from a trusted clean checkout and its built binary."""
import argparse
import hashlib
import io
import json
import mmap
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tomllib

from Notices import ROOT, SQLCIPHER_COMMIT, digest, notices


def command(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def build_remaps():
    home = Path.home().absolute()
    cargo = Path(os.environ.get("CARGO_HOME", home / ".cargo")).absolute()
    locations = [(home, "/build"), (cargo, "/cargo")]
    if os.environ.get("CARGO_TARGET_DIR"):
        locations.append((Path(os.environ["CARGO_TARGET_DIR"]).absolute(), "/target"))
    locations.append((ROOT, "/source"))
    remaps = []
    for path, replacement in locations:
        for spelling in (path, path.resolve()):
            if spelling == Path(spelling.anchor) or "\x1f" in str(spelling):
                raise SystemExit("Build path cannot be represented safely")
            pair = (str(spelling), replacement)
            if pair not in remaps:
                remaps.append(pair)
    return remaps


def build_rustflags():
    # Cargo gives encoded flags precedence over its whitespace-separated form.
    previous = os.environ.get("CARGO_ENCODED_RUSTFLAGS")
    if previous is None:
        previous = "\x1f".join(os.environ.get("RUSTFLAGS", "").split())
    flags = ["--remap-path-prefix=" + source + "=" + target
             for source, target in build_remaps()]
    return (previous + "\x1f" if previous else "") + "\x1f".join(flags)


def verify_build_paths(binary):
    prefixes = {os.fsencode(source) for source, _ in build_remaps()}
    with binary.open("rb") as source:
        if not os.fstat(source.fileno()).st_size:
            raise SystemExit("Package binary is empty")
        with mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as contents:
            if any(contents.find(prefix) >= 0 for prefix in prefixes):
                raise SystemExit("Binary retains private build paths; rebuild with package path remapping")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-rustflags", action="store_true",
                        help="Print encoded flags for capture in CARGO_ENCODED_RUSTFLAGS")
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--sqlcipher-source", type=Path)
    parser.add_argument("--output", type=Path,
                        help="New .tar.gz path; existing output is refused")
    args = parser.parse_args()
    if args.build_rustflags:
        if any((args.binary, args.sqlcipher_source, args.output)):
            parser.error("Build flags do not accept package arguments")
        print(build_rustflags(), end="")
        return
    if not all((args.binary, args.sqlcipher_source, args.output)):
        parser.error("Packaging requires --binary, --sqlcipher-source and --output")
    binary = args.binary.resolve(strict=True)
    sqlcipher = args.sqlcipher_source.resolve(strict=True)
    output = args.output.absolute()
    if output.suffixes[-2:] != [".tar", ".gz"] or output.exists():
        raise ValueError("Select a new .tar.gz output")
    verify_build_paths(binary)
    if command("git", "status", "--porcelain"):
        raise ValueError("Commit source changes before packaging")
    package = tomllib.loads((ROOT / "Cargo.toml").read_text())["package"]
    version = package["version"]
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?", version):
        raise ValueError("Unsupported package version")
    if command(str(binary), "--version") != "hypernet-relay-chat " + version:
        raise ValueError("Binary version does not match the checkout")
    header = command("readelf", "--file-header", str(binary))
    if "Advanced Micro Devices X86-64" not in header or "ELF64" not in header:
        raise ValueError("Only Linux x86_64 ELF packages are supported")
    versions = command("readelf", "--version-info", str(binary))
    required = sorted(set(re.findall(r"Name: (GLIBC_[0-9.]+)", versions)),
                      key=lambda v: tuple(map(int, v[6:].split("."))))
    if not required:
        raise ValueError("Cannot determine the binary's GNU libc requirement")
    needed = re.findall(r"\(NEEDED\).*\[(.+?)\]",
                        command("readelf", "--dynamic", str(binary)))
    revision = command("git", "rev-parse", "HEAD")
    timestamp = int(command("git", "show", "-s", "--format=%ct", "HEAD"))
    notice_text, dependencies, covered_sources = notices(sqlcipher)
    files = {"Bin/hrc": binary, "README.md": ROOT / "README.md", "LICENSE": ROOT / "LICENSE"}
    files.update(covered_sources)
    for directory in ("Documentation", "Tools", "Packaging"):
        tracked = command("git", "ls-files", "-z", directory).split("\0")
        for filename in filter(None, tracked):
            path = ROOT / filename
            if path.is_symlink() or not path.is_file():
                raise ValueError("Package input must be a regular file: " + filename)
            files[filename] = path
    # The release source archive accompanies this package. These files identify
    # the locked build without retaining workstation paths or private state.
    for filename in ("Cargo.toml", "Cargo.lock"):
        files[filename] = ROOT / filename
    generated = {
        "Documentation/DependencyNotices.txt": notice_text.encode(),
        "Documentation/Dependencies.json": (json.dumps(dependencies, indent=2) + "\n").encode(),
    }
    manifest = {
        "product": "HyperNet Relay Chat", "version": version,
        "target": "x86_64-unknown-linux-gnu", "sourceCommit": revision,
        "rustCompiler": command("rustc", "--version"),
        "sqlcipherSourceCommit": SQLCIPHER_COMMIT,
        "minimumGlibc": required[-1], "requiredSharedLibraries": needed,
        "files": {name: {"sha256": digest(path), "bytes": path.stat().st_size}
                  for name, path in sorted(files.items())},
    }
    for name, data in generated.items():
        manifest["files"][name] = {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
    generated["Package.json"] = (json.dumps(manifest, indent=2) + "\n").encode()
    prefix = "HRC-" + version + "-linux-x86_64"
    # O_EXCL prevents accidental replacement even if another process creates it
    # after the initial check. No extraction or installation runs here.
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as sink, tarfile.open(fileobj=sink, mode="w:gz") as archive:
            for name in sorted(files.keys() | generated.keys()):
                data = generated.get(name)
                info = tarfile.TarInfo(prefix + "/" + name)
                info.mode = 0o755 if name in ("Bin/hrc", "Tools/Install.sh") else 0o644
                info.mtime = timestamp
                info.size = len(data) if data is not None else files[name].stat().st_size
                if data is not None:
                    archive.addfile(info, io.BytesIO(data))
                else:
                    with files[name].open("rb") as source:
                        archive.addfile(info, source)
    except BaseException:
        output.unlink()
        raise
    print(json.dumps({"archive": output.name, "sha256": digest(output), "bytes": output.stat().st_size,
                      "sourceCommit": revision, "minimumGlibc": required[-1]}, indent=2))


if __name__ == "__main__":
    main()
