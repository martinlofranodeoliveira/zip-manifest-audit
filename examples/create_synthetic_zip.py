#!/usr/bin/env python3
"""Create a small, deterministic ZIP with synthetic audit findings.

Only writes a new ZIP at the explicitly selected output path. It does not
extract anything or access any archive member as a local path.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import stat
import warnings
import zipfile


def _entry(name: str, mode: int = stat.S_IFREG | 0o644) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
    info.create_system = 3  # Unix file-type bits for the symlink example.
    info.external_attr = mode << 16
    info.compress_type = zipfile.ZIP_DEFLATED
    return info


def create_synthetic_zip(output: Path) -> None:
    """Create an example archive; refuse to replace an existing file."""
    with zipfile.ZipFile(output, mode="x") as archive:
        archive.writestr(_entry("documents/", stat.S_IFDIR | 0o755), b"")
        archive.writestr(_entry("documents/hello.txt"), b"Synthetic example.\n")
        archive.writestr(_entry("../outside.txt"), b"Synthetic parent segment.\n")
        archive.writestr(_entry("/absolute.txt"), b"Synthetic absolute name.\n")
        archive.writestr(_entry("windows\\name.txt"), b"Synthetic backslash.\n")
        archive.writestr(_entry("documents/Readme.txt"), b"First case variant.\n")
        archive.writestr(_entry("documents/readme.txt"), b"Second case variant.\n")
        archive.writestr(_entry("duplicate.txt"), b"First occurrence.\n")
        with warnings.catch_warnings():
            warnings.filterwarnings(
                "ignore", message="Duplicate name:.*", category=UserWarning
            )
            archive.writestr(_entry("duplicate.txt"), b"Second occurrence.\n")
        archive.writestr(_entry("shortcut", stat.S_IFLNK | 0o777), b"documents/hello.txt")
        archive.writestr(_entry("repeated.txt"), b"x" * (2 * 1024 * 1024))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "output", nargs="?", type=Path, default=Path("synthetic.zip"),
        help="new ZIP to create (default: synthetic.zip; existing files are refused)",
    )
    args = parser.parse_args()
    try:
        create_synthetic_zip(args.output)
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        parser.exit(2, f"Could not create example ZIP: {exc}\n")
    print(f"Created {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
