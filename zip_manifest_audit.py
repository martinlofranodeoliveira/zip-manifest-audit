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

__all__ = ["ArchiveError", "audit_zip", "compare_zips"]

MAX_SOURCE_BYTES = 16 * 1024 * 1024
MAX_ENTRIES = 10_000
MAX_RATIO = 1_000_000
_ERROR_MESSAGE = "Unable to audit ZIP archive."
_COMPARISON_FIELDS = (
    "is_dir", "compressed_size", "uncompressed_size", "crc32",
    "compression", "encrypted", "is_symlink",
)


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


def _occurrences(entries: list[dict]) -> dict[tuple[str, int], dict]:
    """Index exact original names without losing duplicate directory entries."""
    counts: dict[str, int] = {}
    indexed = {}
    for entry in entries:
        name = entry["name"]
        occurrence = counts.get(name, 0)
        indexed[(name, occurrence)] = entry
        counts[name] = occurrence + 1
    return indexed


def compare_zips(
    before: str | os.PathLike[str],
    after: str | os.PathLike[str],
    *,
    max_ratio: int = 1000,
) -> dict:
    """Compare bounded ZIP directory claims without reading member contents.

    Both sources are audited independently. Entries match by exact original
    name and zero-based occurrence of that name, with no path normalization.
    Absolute directory indices are ignored for comparison. Equal metadata does
    not establish equal payloads; timestamps, comments, and permission bits
    other than the existing symlink flag are outside the delta scope.
    """
    before_report = audit_zip(before, max_ratio=max_ratio)
    after_report = audit_zip(after, max_ratio=max_ratio)
    before_entries = _occurrences(before_report["entries"])
    after_entries = _occurrences(after_report["entries"])
    added = []
    changed = []
    unchanged = 0
    for (name, occurrence), after_entry in after_entries.items():
        before_entry = before_entries.get((name, occurrence))
        if before_entry is None:
            added.append({"name": name, "occurrence": occurrence, "entry": after_entry})
            continue
        fields = [
            field for field in _COMPARISON_FIELDS
            if before_entry[field] != after_entry[field]
        ]
        if fields:
            changed.append({
                "name": name,
                "occurrence": occurrence,
                "before": before_entry,
                "after": after_entry,
                "fields": fields,
            })
        else:
            unchanged += 1
    removed = [
        {"name": name, "occurrence": occurrence, "entry": entry}
        for (name, occurrence), entry in before_entries.items()
        if (name, occurrence) not in after_entries
    ]
    return {
        "before": before_report,
        "after": after_report,
        "added": added,
        "removed": removed,
        "changed": changed,
        "summary": {
            "added": len(added),
            "removed": len(removed),
            "changed": len(changed),
            "unchanged": unchanged,
        },
    }


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


def _comparison_markdown(report: dict) -> str:
    summary = report["summary"]
    lines = [
        "# ZIP manifest comparison",
        "",
        "Central-directory claims only. Equal metadata does not establish equal member contents.",
        "Member contents and CRC integrity were not checked.",
        "",
        "Members match by exact original name and zero-based occurrence of that name.",
        "Directory indices, timestamps, comments and other permission bits are outside delta scope.",
        "",
        f"Before SHA-256: `{report['before']['sha256']}`",
        f"After SHA-256: `{report['after']['sha256']}`",
        "",
        f"Added: {summary['added']} | Removed: {summary['removed']} | "
        f"Changed: {summary['changed']} | Unchanged: {summary['unchanged']}",
    ]
    for key, title in (("added", "Added"), ("removed", "Removed")):
        lines.extend([
            "", f"## {title}", "",
            "| Name | Occurrence | Directory index |",
            "| --- | --- | --- |",
        ])
        for row in report[key]:
            lines.append(
                f"| {_markdown_name(row['name'])} | {row['occurrence']} | {row['entry']['index']} |"
            )
        if not report[key]:
            lines.extend(["", "None."])
    lines.extend([
        "", "## Changed", "",
        "| Name | Occurrence | Field | Before | After |",
        "| --- | --- | --- | --- | --- |",
    ])
    for row in report["changed"]:
        for field in row["fields"]:
            before = json.dumps(row["before"][field], ensure_ascii=True)
            after = json.dumps(row["after"][field], ensure_ascii=True)
            lines.append(
                f"| {_markdown_name(row['name'])} | {row['occurrence']} | {field} | "
                f"`{before}` | `{after}` |"
            )
    if not report["changed"]:
        lines.extend(["", "None."])
    # Include both complete audits, retaining their existing inert rendering.
    # Demote their headings so each stays inside its comparison subsection.
    for key, title in (("before", "Before audit"), ("after", "After audit")):
        lines.extend(["", f"## {title}", ""])
        lines.extend(
            "##" + line if line.startswith("#") else line
            for line in _markdown(report[key]).splitlines()
        )
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
    parser.add_argument(
        "--compare", metavar="OTHERZIP", help="compare with a second regular ZIP source"
    )
    parser.add_argument("--max-ratio", type=int, default=1000, metavar="N")
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    parser.add_argument(
        "--fail-on-findings", action="store_true",
        help="exit 1 when metadata findings exist in either audited archive",
    )
    parser.add_argument(
        "--fail-on-changes", action="store_true", help="exit 1 for comparison deltas (requires --compare)"
    )
    arguments = parser.parse_args(argv)
    if arguments.fail_on_changes and arguments.compare is None:
        parser.error("--fail-on-changes requires --compare")
    try:
        if arguments.compare is not None:
            report = compare_zips(
                arguments.zip, arguments.compare, max_ratio=arguments.max_ratio
            )
        else:
            report = audit_zip(arguments.zip, max_ratio=arguments.max_ratio)
    except ArchiveError:
        print(f"error: {_ERROR_MESSAGE}", file=sys.stderr)
        return 2
    if arguments.format == "json":
        output = json.dumps(report, ensure_ascii=True, indent=2) + "\n"
    elif arguments.compare is not None:
        output = _comparison_markdown(report)
    else:
        output = _markdown(report)
    sys.stdout.write(output)
    if arguments.compare is not None:
        findings = report["before"]["findings"] or report["after"]["findings"]
        changes = any(report["summary"][key] for key in ("added", "removed", "changed"))
    else:
        findings = report["findings"]
        changes = False
    return 1 if (
        (arguments.fail_on_findings and findings)
        or (arguments.fail_on_changes and changes)
    ) else 0


if __name__ == "__main__":
    raise SystemExit(main())
