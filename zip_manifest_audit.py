"""Inventory untrusted ZIP central-directory metadata without reading members.

This module does not extract members, inspect their contents, verify CRC values,
or determine whether an archive is safe. It has no third-party dependencies.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import stat
import sys
import zipfile
from typing import Sequence

__all__ = ["ArchiveError", "audit_zip"]

MAX_SOURCE_BYTES = 16 * 1024 * 1024
MAX_ENTRIES = 10_000
MAX_RATIO = 1_000_000
_ERROR_MESSAGE = "Unable to audit ZIP archive."


class ArchiveError(ValueError):
    """The source, directory metadata, or audit options could not be accepted."""


def _snapshot(path: str | os.PathLike[str]) -> bytes:
    """Open a regular source read-only and take one bounded byte snapshot."""
    descriptor = None
    try:
        # O_NONBLOCK allows a FIFO to be rejected by fstat without waiting for a
        # writer. It has no effect on an ordinary regular file.
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(os.fspath(path), flags)
        with os.fdopen(descriptor, "rb") as source:
            descriptor = None  # the context manager now owns the descriptor
            metadata = os.fstat(source.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                raise ArchiveError(_ERROR_MESSAGE)
            if metadata.st_size > MAX_SOURCE_BYTES:
                raise ArchiveError(_ERROR_MESSAGE)
            snapshot = source.read(MAX_SOURCE_BYTES + 1)
            if len(snapshot) > MAX_SOURCE_BYTES:
                raise ArchiveError(_ERROR_MESSAGE)
            return snapshot
    finally:
        if descriptor is not None:
            os.close(descriptor)


def audit_zip(
    path: str | os.PathLike[str], *, max_ratio: int = 1000
) -> dict:
    """Return deterministic central-directory claims and metadata findings.

    The source must be a regular file no larger than 16 MiB. A single snapshot
    supplies both the SHA-256 digest and ZIP parsing. No member contents are
    opened. ``max_ratio`` must be an actual int from 1 through 1,000,000.

    All invalid input and metadata/IO errors become a generic ``ArchiveError``;
    error text never includes the source path or an archive member name.
    """
    if type(max_ratio) is not int or not 1 <= max_ratio <= MAX_RATIO:
        raise ArchiveError(_ERROR_MESSAGE)
    try:
        snapshot = _snapshot(path)
        with zipfile.ZipFile(io.BytesIO(snapshot), mode="r") as archive:
            # zipfile has already built directory metadata at this point. The
            # limit does not prevent that initial allocation by the stdlib.
            directory = archive.infolist()
            if len(directory) > MAX_ENTRIES:
                raise ArchiveError(_ERROR_MESSAGE)

            entries = []
            findings = []
            seen_names: set[str] = set()
            folded_names: dict[str, set[str]] = {}
            files = directories = uncompressed = compressed = 0

            for index, info in enumerate(directory):
                # ZipInfo.filename is truncated at NUL. orig_filename retains
                # the decoded central-directory name, including any NUL.
                name = info.orig_filename
                is_dir = name.endswith("/")
                is_symlink = stat.S_ISLNK(info.external_attr >> 16)
                encrypted = bool(info.flag_bits & 1)
                entry = {
                    "index": index,
                    "name": name,
                    "is_dir": is_dir,
                    "compressed_size": info.compress_size,
                    "uncompressed_size": info.file_size,
                    "crc32": f"{info.CRC:08x}",
                    "compression": info.compress_type,
                    "encrypted": encrypted,
                    "is_symlink": is_symlink,
                }
                entries.append(entry)
                directories += int(is_dir)
                files += int(not is_dir)
                uncompressed += info.file_size
                compressed += info.compress_size

                normalized = name.replace("\\", "/")
                folded = normalized.casefold()
                prior = folded_names.get(folded)
                collision = prior is not None and (
                    len(prior) > 1 or name not in prior
                )
                drive_prefix = (
                    len(name) >= 2
                    and name[1] == ":"
                    and ("a" <= name[0] <= "z" or "A" <= name[0] <= "Z")
                )
                high_ratio = info.file_size > 0 and (
                    info.compress_size == 0
                    or info.file_size > max_ratio * info.compress_size
                )
                # Tuple order is the public, deterministic finding code order.
                checks = (
                    ("absolute_path", name.startswith(("/", "\\")) or drive_prefix),
                    ("parent_segment", ".." in normalized.split("/")),
                    ("backslash_path", "\\" in name),
                    (
                        "control_character",
                        any(ord(character) < 32 or ord(character) == 127 for character in name),
                    ),
                    ("duplicate_name", name in seen_names),
                    ("case_collision", collision),
                    ("symlink", is_symlink),
                    ("encrypted", encrypted),
                    ("high_ratio", high_ratio),
                    ("other_compression", info.compress_type not in (0, 8)),
                )
                findings.extend(
                    {"code": code, "index": index, "path": name}
                    for code, applies in checks
                    if applies
                )
                seen_names.add(name)
                folded_names.setdefault(folded, set()).add(name)

        return {
            "sha256": hashlib.sha256(snapshot).hexdigest(),
            "entries": entries,
            "summary": {
                "files": files,
                "directories": directories,
                "total_uncompressed_bytes": uncompressed,
                "total_compressed_bytes": compressed,
            },
            "findings": findings,
        }
    except Exception:
        # A boundary around untrusted filenames/metadata also covers decoding,
        # struct, OS, unsupported-version, and invalid-container errors. Do not
        # expose exception strings, source paths, or archive-controlled text.
        raise ArchiveError(_ERROR_MESSAGE) from None


def _markdown_name(name: str) -> str:
    """Render a JSON-style literal that cannot supply markup or link syntax."""
    literal = json.dumps(name, ensure_ascii=True)
    # Code spans stop Markdown interpretation. Escaping these characters also
    # prevents table splitting, raw HTML, code-span termination, and bare-link
    # or email recognition by renderers with automatic link extensions.
    escaped = "".join(
        f"\\u{ord(character):04x}" if character in "&<>|`:.@" else character
        for character in literal
    )
    return f"`{escaped}`"


def _markdown(report: dict) -> str:
    summary = report["summary"]
    lines = [
        "# ZIP manifest audit",
        "",
        "Central-directory claims only. Member contents and CRC integrity were not checked.",
        "",
        f"SHA-256: `{report['sha256']}`",
        "",
        f"Files: {summary['files']} | Directories: {summary['directories']} | "
        f"Claimed uncompressed bytes: {summary['total_uncompressed_bytes']} | "
        f"Claimed compressed bytes: {summary['total_compressed_bytes']}",
        "",
        "Names use escaped JSON-style literals; punctuation escapes keep identifiers inert.",
        "",
        "## Entries",
        "",
        "| Index | Name | Directory | Compressed | Uncompressed | CRC32 | Method | Encrypted | Symlink |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for entry in report["entries"]:
        lines.append(
            f"| {entry['index']} | {_markdown_name(entry['name'])} | "
            f"{str(entry['is_dir']).lower()} | {entry['compressed_size']} | "
            f"{entry['uncompressed_size']} | {entry['crc32']} | {entry['compression']} | "
            f"{str(entry['encrypted']).lower()} | {str(entry['is_symlink']).lower()} |"
        )
    lines.extend(
        ["", "## Findings", "", "| Index | Code | Path |", "| --- | --- | --- |"]
    )
    for finding in report["findings"]:
        lines.append(
            f"| {finding['index']} | {finding['code']} | {_markdown_name(finding['path'])} |"
        )
    if not report["findings"]:
        lines.extend(["", "No metadata findings for the checks performed."])
    return "\n".join(lines) + "\n"


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        # argparse normally repeats rejected argument values in diagnostics.
        self.exit(2, f"error: {_ERROR_MESSAGE}\n")


def main(argv: Sequence[str] | None = None) -> int:
    """Command-line entry point; findings affect status only when opted in."""
    parser = _Parser(
        prog="zip_manifest_audit",
        description="Audit ZIP central-directory metadata without reading members.",
    )
    parser.add_argument("zip", metavar="ZIP", help="regular ZIP source, at most 16 MiB")
    parser.add_argument("--max-ratio", type=int, default=1000, metavar="N")
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    parser.add_argument(
        "--fail-on-findings", action="store_true", help="exit 1 when metadata findings exist"
    )
    arguments = parser.parse_args(argv)
    try:
        report = audit_zip(arguments.zip, max_ratio=arguments.max_ratio)
    except ArchiveError:
        print(f"error: {_ERROR_MESSAGE}", file=sys.stderr)
        return 2
    output = (
        json.dumps(report, ensure_ascii=True, indent=2) + "\n"
        if arguments.format == "json"
        else _markdown(report)
    )
    sys.stdout.write(output)
    return 1 if arguments.fail_on_findings and report["findings"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
