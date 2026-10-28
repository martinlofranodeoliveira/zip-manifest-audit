"""Synthetic comparison contracts, without extracting or reading ZIP members."""

from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import struct
import tempfile
import unittest
from unittest import mock
import warnings
import zipfile

import zip_manifest_audit as audit


def make_zip(members=(), *, comment=b""):
    stream = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(stream, "w") as archive:
            archive.comment = comment
            for name, data in members:
                entry = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
                archive.writestr(entry, data)
    return stream.getvalue()


def patch_entry(data, index=0, **changes):
    result = bytearray(data)
    end = result.rindex(b"PK\x05\x06")
    position = struct.unpack_from("<I", result, end + 16)[0]
    for _ in range(index):
        name, extra, comment = struct.unpack_from("<HHH", result, position + 28)
        position += 46 + name + extra + comment
    fields = {
        "flags": (8, "H"), "method": (10, "H"), "crc": (16, "I"),
        "compressed": (20, "I"), "uncompressed": (24, "I"),
        "external_attr": (38, "I"),
    }
    for field, value in changes.items():
        if field == "name":
            length = struct.unpack_from("<H", result, position + 28)[0]
            if len(value) != length:
                raise AssertionError("Synthetic replacement name must preserve length")
            result[position + 46:position + 46 + length] = value
        else:
            relative, kind = fields[field]
            struct.pack_into("<" + kind, result, position + relative, value)
    return bytes(result)


class ComparisonTests(unittest.TestCase):
    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory()
        self.addCleanup(self.workspace.cleanup)
        self.before = Path(self.workspace.name) / "before.zip"
        self.after = Path(self.workspace.name) / "after.zip"

    def write(self, before=(), after=()):
        self.before.write_bytes(make_zip(before))
        self.after.write_bytes(make_zip(after))

    def compare(self, **options):
        return audit.compare_zips(self.before, self.after, **options)

    def cli(self, *arguments):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            try:
                status = audit.main(list(map(str, arguments)))
            except SystemExit as exited:
                status = exited.code
        return status, output.getvalue(), errors.getvalue()

    def test_complete_reports_changes_and_summary(self):
        self.write(
            [("removed", b"old"), ("changed", b"old"), ("same", b"keep")],
            [("same", b"keep"), ("added", b"new"), ("changed", b"new")],
        )
        result = self.compare()
        self.assertEqual(set(result), {"before", "after", "added", "removed", "changed", "summary"})
        self.assertEqual(result["before"], audit.audit_zip(self.before))
        self.assertEqual(result["after"], audit.audit_zip(self.after))
        self.assertEqual(result["summary"], {"added": 1, "removed": 1, "changed": 1, "unchanged": 1})
        self.assertEqual(result["added"], [{
            "name": "added", "occurrence": 0, "entry": result["after"]["entries"][1],
        }])
        self.assertEqual(result["removed"], [{
            "name": "removed", "occurrence": 0, "entry": result["before"]["entries"][0],
        }])
        self.assertEqual(result["changed"], [{
            "name": "changed", "occurrence": 0,
            "before": result["before"]["entries"][1],
            "after": result["after"]["entries"][2], "fields": ["crc32"],
        }])
        self.assertEqual(result, self.compare())

    def test_unique_reordering_ignores_directory_indices(self):
        members = [("one", b"1"), ("two", b"2"), ("folder/", b"")]
        self.write(members, list(reversed(members)))
        result = self.compare()
        self.assertEqual(result["summary"], {"added": 0, "removed": 0, "changed": 0, "unchanged": 3})
        self.assertNotEqual(result["before"]["sha256"], result["after"]["sha256"])
        self.assertEqual(result["added"] + result["removed"] + result["changed"], [])

    def test_duplicate_occurrences_are_not_collapsed(self):
        self.write(
            [("dup", b"first"), ("keep", b""), ("dup", b"second"), ("gone", b"0"), ("gone", b"1")],
            [("dup", b"first"), ("dup", b"changed"), ("dup", b"third"), ("keep", b""), ("gone", b"0")],
        )
        result = self.compare()
        self.assertEqual(result["summary"], {"added": 1, "removed": 1, "changed": 1, "unchanged": 3})
        self.assertEqual([(row["name"], row["occurrence"]) for row in result["added"]], [("dup", 2)])
        self.assertEqual([(row["name"], row["occurrence"]) for row in result["removed"]], [("gone", 1)])
        self.assertEqual([(row["name"], row["occurrence"]) for row in result["changed"]], [("dup", 1)])

    def test_delta_order_follows_corresponding_directory(self):
        self.write(
            [("remove-z", b""), ("change-a", b"a"), ("remove-a", b""), ("change-z", b"z")],
            [("add-z", b""), ("change-z", b"Z"), ("add-a", b""), ("change-a", b"A")],
        )
        result = self.compare()
        for kind, names in (
            ("added", ["add-z", "add-a"]),
            ("removed", ["remove-z", "remove-a"]),
            ("changed", ["change-z", "change-a"]),
        ):
            self.assertEqual([row["name"] for row in result[kind]], names)

    def test_exact_names_do_not_normalize_case_slashes_unicode_or_nul(self):
        self.write(
            [("A/x", b""), ("Straße", b""), ("nulXold", b"")],
            [("a\\X", b""), ("STRASSE", b""), ("nulXnew", b"")],
        )
        self.before.write_bytes(patch_entry(self.before.read_bytes(), 2, name=b"nul\x00old"))
        self.after.write_bytes(patch_entry(self.after.read_bytes(), 2, name=b"nul\x00new"))
        result = self.compare()
        self.assertEqual(result["summary"], {"added": 3, "removed": 3, "changed": 0, "unchanged": 0})
        self.assertEqual(result["removed"][-1]["name"], "nul\x00old")
        self.assertEqual(result["added"][-1]["name"], "nul\x00new")

    def test_changed_field_order_and_original_entry_values(self):
        self.write([("member", b"abc")], [("member", b"abc")])
        self.after.write_bytes(patch_entry(
            self.after.read_bytes(), flags=1, method=99, crc=0x1234ABCD,
            compressed=2, uncompressed=5000,
            external_attr=(stat.S_IFLNK | 0o777) << 16,
        ))
        result = self.compare()
        change = result["changed"][0]
        self.assertEqual(change["fields"], [
            "compressed_size", "uncompressed_size", "crc32", "compression", "encrypted", "is_symlink",
        ])
        self.assertEqual(change["after"]["crc32"], "1234abcd")
        self.assertEqual(change["before"]["compressed_size"], 3)
        self.assertTrue(result["after"]["findings"])

    def test_directory_rename_is_removal_and_addition(self):
        self.write([("folder/", b"")], [("folder", b"")])
        result = self.compare()
        self.assertEqual(result["summary"], {"added": 1, "removed": 1, "changed": 0, "unchanged": 0})
        self.assertTrue(result["removed"][0]["entry"]["is_dir"])
        self.assertFalse(result["added"][0]["entry"]["is_dir"])

    def test_empty_archives_and_comments_outside_delta_scope(self):
        self.write()
        self.assertEqual(self.compare()["summary"], {"added": 0, "removed": 0, "changed": 0, "unchanged": 0})
        self.before.write_bytes(make_zip([("member", b"abc")], comment=b"first"))
        self.after.write_bytes(make_zip([("member", b"abc")], comment=b"second"))
        result = self.compare()
        self.assertEqual(result["summary"]["unchanged"], 1)
        self.assertEqual(result["changed"], [])
        self.assertNotEqual(result["before"]["sha256"], result["after"]["sha256"])

    def test_both_snapshots_read_only_without_payload_operations(self):
        self.write([("member", b"old")], [("member", b"new")])
        originals = {path: path.read_bytes() for path in (self.before, self.after)}
        real_open = os.open
        opened = []

        def read_only_open(path, flags):
            self.assertEqual(flags & os.O_ACCMODE, os.O_RDONLY)
            self.assertFalse(flags & (os.O_CREAT | os.O_TRUNC | os.O_APPEND))
            opened.append(Path(path))
            return real_open(path, flags)

        with mock.patch.object(audit.os, "open", side_effect=read_only_open), mock.patch.multiple(
            zipfile.ZipFile,
            open=mock.Mock(side_effect=AssertionError("member open forbidden")),
            read=mock.Mock(side_effect=AssertionError("member read forbidden")),
            testzip=mock.Mock(side_effect=AssertionError("CRC verification forbidden")),
            extract=mock.Mock(side_effect=AssertionError("extraction forbidden")),
            extractall=mock.Mock(side_effect=AssertionError("extraction forbidden")),
        ):
            result = self.compare()
        self.assertEqual(opened, [self.before, self.after])
        for key, path in (("before", self.before), ("after", self.after)):
            self.assertEqual(path.read_bytes(), originals[path])
            self.assertEqual(result[key]["sha256"], hashlib.sha256(originals[path]).hexdigest())
        self.assertEqual(set(self.before.parent.iterdir()), {self.before, self.after})

    def test_ratio_applies_independently_and_options_are_strict(self):
        data = patch_entry(make_zip([("member", b"abc")]), compressed=1, uncompressed=1001)
        self.before.write_bytes(data)
        self.after.write_bytes(data)
        result = self.compare(max_ratio=1000)
        self.assertEqual([row["code"] for row in result["before"]["findings"]], ["high_ratio"])
        self.assertEqual(result["before"]["findings"], result["after"]["findings"])
        self.assertEqual(self.compare(max_ratio=1001)["before"]["findings"], [])
        for value in (True, 0, 1_000_001, 1.5, "1000"):
            with self.subTest(value=value), self.assertRaises(audit.ArchiveError):
                self.compare(max_ratio=value)

    def test_invalid_and_oversized_sources_reject_either_side_privately(self):
        for bad_side in (self.before, self.after):
            self.write()
            bad_side.write_bytes(b"private broken archive")
            with self.assertRaises(audit.ArchiveError) as caught:
                self.compare()
            self.assertEqual(str(caught.exception), "Unable to audit ZIP archive.")
            with bad_side.open("wb") as source:
                source.truncate(audit.MAX_SOURCE_BYTES + 1)
            with self.assertRaises(audit.ArchiveError):
                self.compare()
        with mock.patch.object(audit, "MAX_ENTRIES", 1):
            for before, after in (
                ([("a", b""), ("b", b"")], []),
                ([], [("a", b""), ("b", b"")]),
            ):
                self.write(before, after)
                with self.assertRaises(audit.ArchiveError):
                    self.compare()

    def test_cli_change_and_finding_exit_flags_are_independent(self):
        self.write([("old", b"")], [("new", b"")])
        arguments = (self.before, "--compare", self.after)
        status, output, errors = self.cli(*arguments)
        self.assertEqual((status, errors), (0, ""))
        self.assertEqual(json.loads(output), self.compare())
        self.assertEqual(self.cli(*arguments, "--fail-on-changes")[0], 1)
        self.assertEqual(self.cli(*arguments, "--fail-on-findings")[0], 0)
        for before, after in (
            ([("../finding", b"")], [("normal", b"")]),
            ([("normal", b"")], [("../finding", b"")]),
        ):
            self.write(before, after)
            self.assertEqual(self.cli(*arguments, "--fail-on-findings")[0], 1)
        self.write([("../finding", b"")], [("../finding", b"")])
        self.assertEqual(self.cli(*arguments, "--fail-on-changes")[0], 0)
        self.assertEqual(self.cli(*arguments, "--fail-on-changes", "--fail-on-findings")[0], 1)

    def test_cli_argument_and_second_source_errors_emit_no_partial_report(self):
        self.write()
        for arguments in (
            (self.before, "--fail-on-changes"),
            (self.before, "--compare", "private-missing.zip"),
            (self.before, "--compare", self.after, "--max-ratio", "0"),
        ):
            with self.subTest(arguments=arguments):
                self.assertEqual(self.cli(*arguments), (2, "", "error: Unable to audit ZIP archive.\n"))
        self.after.write_bytes(b"private broken archive")
        self.assertEqual(
            self.cli(self.before, "--compare", self.after),
            (2, "", "error: Unable to audit ZIP archive.\n"),
        )

    def test_comparison_markdown_keeps_all_name_positions_inert(self):
        danger = '<script>x</script>|[link](https://example.test)\n`code` person@example.test'
        self.write(
            [(danger + " removed", b""), (danger + " changed", b"old")],
            [(danger + " added", b""), (danger + " changed", b"new")],
        )
        status, output, errors = self.cli(self.before, "--compare", self.after, "--format", "markdown")
        self.assertEqual((status, errors), (0, ""))
        self.assertTrue(output.isascii())
        for fragment in ("<script>", "https://", "@", "\r", "\t"):
            self.assertNotIn(fragment, output)
        for escaped in ("\\u003cscript\\u003e", "\\u007c", "\\u0060code\\u0060", "\\n"):
            self.assertIn(escaped, output)
        self.assertIn("Equal metadata does not establish equal member contents.", output)
        self.assertIn("## Before audit", output)
        self.assertIn("## After audit", output)
        self.assertIn("crc32", output)


if __name__ == "__main__":
    unittest.main()
