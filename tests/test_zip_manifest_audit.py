"""Synthetic, offline contract tests; no private fixtures or extracted files."""

from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import warnings
import zipfile
import zlib

import zip_manifest_audit as audit


ROOT = Path(__file__).resolve().parents[1]


def make_zip(members=()) -> bytes:
    stream = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(stream, "w") as archive:
            for name, data in members:
                info = name if isinstance(name, zipfile.ZipInfo) else zipfile.ZipInfo(name)
                info.date_time = (2020, 1, 1, 0, 0, 0)
                archive.writestr(info, data)
    return stream.getvalue()


def central_offsets(data: bytes) -> list[int]:
    end = data.rindex(b"PK\x05\x06")
    count = struct.unpack_from("<H", data, end + 10)[0]
    offset = struct.unpack_from("<I", data, end + 16)[0]
    offsets = []
    for _ in range(count):
        if data[offset : offset + 4] != b"PK\x01\x02":
            raise AssertionError("Invalid synthetic central directory")
        offsets.append(offset)
        name, extra, comment = struct.unpack_from("<HHH", data, offset + 28)
        offset += 46 + name + extra + comment
    return offsets


def patch_entry(data: bytes, index: int, **changes) -> bytes:
    result = bytearray(data)
    start = central_offsets(data)[index]
    fields = {
        "flags": (8, "H"),
        "method": (10, "H"),
        "crc": (16, "I"),
        "compressed": (20, "I"),
        "uncompressed": (24, "I"),
        "external_attr": (38, "I"),
    }
    for field, value in changes.items():
        if field == "name":
            length = struct.unpack_from("<H", result, start + 28)[0]
            if len(value) != length:
                raise AssertionError("Replacement synthetic name must preserve length")
            result[start + 46 : start + 46 + length] = value
        else:
            relative, kind = fields[field]
            struct.pack_into("<" + kind, result, start + relative, value)
    return bytes(result)


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory()
        self.addCleanup(self.workspace.cleanup)
        self.path = Path(self.workspace.name) / "source.zip"

    def write(self, data: bytes) -> Path:
        self.path.write_bytes(data)
        return self.path

    def report(self, members=(), **options):
        return audit.audit_zip(self.write(make_zip(members)), **options)

    def codes(self, report, index):
        return [item["code"] for item in report["findings"] if item["index"] == index]

    def test_entry_schema_order_digest_and_unchanged_source(self):
        data = make_zip([("folder/", b"dir"), ("folder/caf\u00e9.txt", b"abc")])
        self.write(data)
        before = hashlib.sha256(self.path.read_bytes()).hexdigest()
        report = audit.audit_zip(self.path)
        self.assertEqual(set(report), {"sha256", "entries", "summary", "findings"})
        self.assertEqual(report["sha256"], before)
        self.assertEqual(report, audit.audit_zip(self.path))
        self.assertEqual(self.path.read_bytes(), data)
        self.assertEqual(
            report["entries"][1],
            {
                "index": 1,
                "name": "folder/caf\u00e9.txt",
                "is_dir": False,
                "compressed_size": 3,
                "uncompressed_size": 3,
                "crc32": f"{zlib.crc32(b'abc'):08x}",
                "compression": 0,
                "encrypted": False,
                "is_symlink": False,
            },
        )
        self.assertEqual(
            report["summary"],
            {
                "files": 1,
                "directories": 1,
                "total_uncompressed_bytes": 6,
                "total_compressed_bytes": 6,
            },
        )
        self.assertEqual(report["findings"], [])

    def test_empty_zip(self):
        report = self.report()
        self.assertEqual(report["entries"], [])
        self.assertEqual(report["findings"], [])
        self.assertEqual(set(report["summary"].values()), {0})

    def test_path_rules_are_literal_and_ascii_drive_only(self):
        names = ["/absolute", "\\absolute", "C:relative", "z:/root", "a/../b", "a\\..\\b"]
        names += ["a/.../b", "a/..hidden", "\u00e9:ordinary", "./ordinary", "normal/"]
        report = self.report([(name, b"") for name in names])
        for index in (0, 1, 2, 3):
            self.assertIn("absolute_path", self.codes(report, index))
        for index in (4, 5):
            self.assertIn("parent_segment", self.codes(report, index))
        for index in range(6, len(names)):
            self.assertEqual(self.codes(report, index), [])
        self.assertIn("backslash_path", self.codes(report, 1))
        self.assertIn("backslash_path", self.codes(report, 5))

    def test_ascii_controls_and_del(self):
        names = ["before" + chr(code) + "after" for code in range(1, 32)] + ["a\x7fb"]
        report = self.report([(name, b"") for name in names])
        self.assertEqual(len(report["findings"]), len(names))
        self.assertTrue(all(item["code"] == "control_character" for item in report["findings"]))

    def test_original_nul_name_and_original_directory_suffix(self):
        data = make_zip([("prefixXsuffix/", b"data")])
        data = patch_entry(data, 0, name=b"prefix\x00suffix/")
        report = audit.audit_zip(self.write(data))
        entry = report["entries"][0]
        self.assertEqual(entry["name"], "prefix\x00suffix/")
        self.assertTrue(entry["is_dir"])
        self.assertEqual(report["summary"]["directories"], 1)
        self.assertEqual(self.codes(report, 0), ["control_character"])
        self.assertEqual(report["findings"][0]["path"], entry["name"])

    def test_duplicates_slash_normalization_and_unicode_casefold(self):
        names = ["A/x", "a\\X", "A/x", "Stra\u00dfe", "STRASSE", "same", "same"]
        report = self.report([(name, b"") for name in names])
        self.assertEqual(self.codes(report, 0), [])
        self.assertEqual(self.codes(report, 1), ["backslash_path", "case_collision"])
        self.assertEqual(self.codes(report, 2), ["duplicate_name", "case_collision"])
        self.assertEqual(self.codes(report, 4), ["case_collision"])
        self.assertEqual(self.codes(report, 6), ["duplicate_name"])

    def test_exact_nul_names_participate_in_duplicate_detection(self):
        data = make_zip([("aXb", b""), ("aXc", b""), ("aXb", b"")])
        for index, name in enumerate((b"a\x00b", b"a\x00c", b"a\x00b")):
            data = patch_entry(data, index, name=name)
        report = audit.audit_zip(self.write(data))
        self.assertEqual(self.codes(report, 1), ["control_character"])
        self.assertEqual(self.codes(report, 2), ["control_character", "duplicate_name"])

    def test_symlink_encryption_and_unknown_compression_metadata(self):
        data = make_zip([("shortcut", b"synthetic target")])
        data = patch_entry(
            data, 0, flags=1, method=99, external_attr=(stat.S_IFLNK | 0o777) << 16
        )
        report = audit.audit_zip(self.write(data))
        self.assertTrue(report["entries"][0]["is_symlink"])
        self.assertTrue(report["entries"][0]["encrypted"])
        self.assertEqual(report["entries"][0]["compression"], 99)
        self.assertEqual(self.codes(report, 0), ["symlink", "encrypted", "other_compression"])

    def test_all_finding_codes_have_contract_order(self):
        name = "C:\\..\\X\x01"
        data = make_zip([(name, b""), ("c:/../x\x01", b""), (name, b"")])
        data = patch_entry(
            data, 2, flags=1, method=99, compressed=0, uncompressed=1,
            external_attr=(stat.S_IFLNK | 0o777) << 16,
        )
        report = audit.audit_zip(self.write(data))
        self.assertEqual(
            self.codes(report, 2),
            ["absolute_path", "parent_segment", "backslash_path", "control_character",
             "duplicate_name", "case_collision", "symlink", "encrypted", "high_ratio",
             "other_compression"],
        )
        indices = [finding["index"] for finding in report["findings"]]
        self.assertEqual(indices, sorted(indices))
        self.assertTrue(all(set(finding) == {"code", "index", "path"} for finding in report["findings"]))

    def test_ratio_uses_claims_strict_threshold_and_zero_denominator(self):
        data = make_zip([(str(index), b"") for index in range(4)])
        for index, compressed, uncompressed in ((0, 2, 2000), (1, 2, 2001), (2, 0, 1), (3, 0, 0)):
            data = patch_entry(data, index, compressed=compressed, uncompressed=uncompressed)
        self.write(data)
        report = audit.audit_zip(self.path)
        self.assertEqual([item["index"] for item in report["findings"]], [1, 2])
        stricter = audit.audit_zip(self.path, max_ratio=999)
        self.assertEqual([item["index"] for item in stricter["findings"]], [0, 1, 2])

    def test_deflate_is_supported_without_a_compression_finding(self):
        entry = zipfile.ZipInfo("deflated")
        entry.compress_type = zipfile.ZIP_DEFLATED
        report = self.report([(entry, b"abcdef" * 100)], max_ratio=1_000_000)
        self.assertEqual(report["entries"][0]["compression"], 8)
        self.assertEqual(report["findings"], [])

    def test_zip64_claims_are_parsed_without_allocating_claimed_sizes(self):
        data = make_zip([("zip64", b"tiny")])
        start = central_offsets(data)[0]
        name_length = struct.unpack_from("<H", data, start + 28)[0]
        extra_at = start + 46 + name_length
        uncompressed, compressed = 5 * 1024**3, 1024**3
        extra = struct.pack("<HHQQ", 1, 16, uncompressed, compressed)
        result = bytearray(data[:extra_at] + extra + data[extra_at:])
        struct.pack_into("<II", result, start + 20, 0xFFFFFFFF, 0xFFFFFFFF)
        struct.pack_into("<H", result, start + 30, len(extra))
        end = result.rindex(b"PK\x05\x06")
        old_directory_size = struct.unpack_from("<I", result, end + 12)[0]
        struct.pack_into("<I", result, end + 12, old_directory_size + len(extra))
        report = audit.audit_zip(self.write(bytes(result)), max_ratio=1)
        self.assertEqual(report["entries"][0]["uncompressed_size"], uncompressed)
        self.assertEqual(report["entries"][0]["compressed_size"], compressed)
        self.assertEqual(self.codes(report, 0), ["high_ratio"])

    def test_payload_is_not_read_and_crc_is_not_verified(self):
        data = patch_entry(make_zip([("member", b"abc")]), 0, crc=0x1234ABCD)
        self.write(data)
        with mock.patch.multiple(
            zipfile.ZipFile,
            open=mock.Mock(side_effect=AssertionError("member open forbidden")),
            read=mock.Mock(side_effect=AssertionError("member read forbidden")),
            testzip=mock.Mock(side_effect=AssertionError("CRC verification forbidden")),
            extract=mock.Mock(side_effect=AssertionError("extraction forbidden")),
            extractall=mock.Mock(side_effect=AssertionError("extraction forbidden")),
        ):
            report = audit.audit_zip(self.path)
        self.assertEqual(report["entries"][0]["crc32"], "1234abcd")
        self.assertEqual(report["findings"], [])

    def test_one_read_only_open_and_one_bounded_source_read(self):
        data = make_zip([("member", b"data")])
        self.write(data)
        real_open, real_fdopen = os.open, os.fdopen
        reads = []
        opens = []

        class ObservedFile:
            def __init__(self, source):
                self.source = source

            def __enter__(self):
                return self

            def __exit__(self, *args):
                self.source.close()

            def fileno(self):
                return self.source.fileno()

            def read(self, limit):
                reads.append(limit)
                return self.source.read(limit)

        def observed_open(path, flags):
            opens.append(flags)
            return real_open(path, flags)

        def observed_fdopen(descriptor, mode):
            self.assertEqual(mode, "rb")
            return ObservedFile(real_fdopen(descriptor, mode))

        with mock.patch.object(audit.os, "open", side_effect=observed_open), mock.patch.object(
            audit.os, "fdopen", side_effect=observed_fdopen
        ):
            report = audit.audit_zip(self.path)
        self.assertEqual(len(opens), 1)
        self.assertEqual(opens[0] & os.O_ACCMODE, os.O_RDONLY)
        self.assertFalse(opens[0] & (os.O_CREAT | os.O_TRUNC | os.O_APPEND))
        self.assertEqual(reads, [audit.MAX_SOURCE_BYTES + 1])
        self.assertEqual(report["sha256"], hashlib.sha256(data).hexdigest())

    def test_strict_ratio_option(self):
        self.write(make_zip())
        for value in (True, False, 0, -1, 1_000_001, 1.0, "1000", None):
            with self.subTest(value=value), self.assertRaises(audit.ArchiveError):
                audit.audit_zip(self.path, max_ratio=value)
        for value in (1, 1_000_000):
            audit.audit_zip(self.path, max_ratio=value)

    def test_invalid_containers_and_metadata_are_generic(self):
        broken_utf8 = patch_entry(make_zip([("x", b"")]), 0, flags=0x800, name=b"\xff")
        for data in (b"", b"not a zip", b"PK\x03\x04", make_zip()[:-1], broken_utf8):
            with self.subTest(length=len(data)), self.assertRaises(audit.ArchiveError) as caught:
                audit.audit_zip(self.write(data))
            self.assertEqual(str(caught.exception), "Unable to audit ZIP archive.")
            self.assertIsInstance(caught.exception, ValueError)

    def test_missing_directory_and_io_failures_are_generic(self):
        for source in (self.path, self.path.parent):
            with self.subTest(source=source), self.assertRaises(audit.ArchiveError) as caught:
                audit.audit_zip(source)
            self.assertEqual(str(caught.exception), "Unable to audit ZIP archive.")
        with mock.patch.object(audit.os, "open", side_effect=PermissionError("private secret path")):
            with self.assertRaises(audit.ArchiveError) as caught:
                audit.audit_zip("private secret path")
        self.assertEqual(str(caught.exception), "Unable to audit ZIP archive.")
        self.write(make_zip())
        with mock.patch.object(audit.os, "fstat", side_effect=OSError("private IO details")):
            with self.assertRaises(audit.ArchiveError) as caught:
                audit.audit_zip(self.path)
        self.assertEqual(str(caught.exception), "Unable to audit ZIP archive.")

    @unittest.skipUnless(hasattr(os, "mkfifo") and hasattr(os, "O_NONBLOCK"), "POSIX FIFO check")
    def test_fifo_is_rejected_without_waiting_for_a_writer(self):
        os.mkfifo(self.path)
        with self.assertRaises(audit.ArchiveError):
            audit.audit_zip(self.path)

    def test_source_size_limit_and_exact_boundary(self):
        empty = make_zip()
        # Prepended bytes are legal ZIP concatenation, requiring no payload read.
        data = b"x" * (audit.MAX_SOURCE_BYTES - len(empty)) + empty
        report = audit.audit_zip(self.write(data))
        self.assertEqual(report["sha256"], hashlib.sha256(data).hexdigest())
        with self.path.open("ab") as source:
            source.write(b"x")
        with self.assertRaises(audit.ArchiveError):
            audit.audit_zip(self.path)

    def test_entry_count_limit(self):
        accepted = make_zip([(str(index), b"") for index in range(10_000)])
        self.assertEqual(len(audit.audit_zip(self.write(accepted))["entries"]), 10_000)
        rejected = make_zip([(str(index), b"") for index in range(10_001)])
        with self.assertRaises(audit.ArchiveError):
            audit.audit_zip(self.write(rejected))

    def cli(self, arguments):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            try:
                status = audit.main(arguments)
            except SystemExit as exited:
                status = exited.code
        return status, output.getvalue(), errors.getvalue()

    def test_cli_default_success_opt_in_findings_and_ascii_json(self):
        self.write(make_zip([("../caf\u00e9", b"")]))
        status, output, errors = self.cli([str(self.path)])
        self.assertEqual((status, errors), (0, ""))
        self.assertTrue(output.isascii())
        self.assertEqual(json.loads(output)["entries"][0]["name"], "../caf\u00e9")
        status, output, errors = self.cli([str(self.path), "--fail-on-findings"])
        self.assertEqual((status, errors), (1, ""))
        self.assertTrue(json.loads(output)["findings"])
        self.write(make_zip([("normal", b"")]))
        self.assertEqual(self.cli([str(self.path), "--fail-on-findings"])[0], 0)

    def test_cli_invalid_input_arguments_and_help(self):
        cases = [[], ["private-secret.zip"], ["--unknown-private-secret"],
                 ["private-secret.zip", "--max-ratio", "private-secret"],
                 ["private-secret.zip", "--max-ratio", "0"],
                 ["private-secret.zip", "--format", "private-secret"]]
        for arguments in cases:
            with self.subTest(arguments=arguments):
                status, output, errors = self.cli(arguments)
                self.assertEqual((status, output), (2, ""))
                self.assertEqual(errors, "error: Unable to audit ZIP archive.\n")
        status, output, errors = self.cli(["--help"])
        self.assertEqual((status, errors), (0, ""))
        self.assertIn("central-directory", output)

    def test_markdown_names_are_inert_even_with_autolink_extensions(self):
        names = ["<script>x</script>|[link](https://example.test/a)\n`code`",
                 "www.example.test", "https://example.test", "person@example.test", "\r\t\x7f"]
        self.write(make_zip([(name, b"") for name in names]))
        status, output, errors = self.cli([str(self.path), "--format", "markdown"])
        self.assertEqual((status, errors), (0, ""))
        self.assertTrue(output.isascii())
        for fragment in ("<script>", "https://", "www.", "@", "\r", "\t", "\x7f"):
            self.assertNotIn(fragment, output)
        self.assertIn("\\u003cscript\\u003e", output)
        self.assertIn("\\u007c", output)
        self.assertIn("\\u0060code\\u0060", output)
        self.assertIn("\\n", output)
        for row in output.splitlines():
            if row.startswith("| 0 |"):
                # Names containing pipes do not add cells in either table.
                self.assertIn(row.count("|"), (4, 10))

    def test_module_entry_point(self):
        self.write(make_zip())
        completed = subprocess.run(
            [sys.executable, "-m", "zip_manifest_audit", str(self.path)],
            cwd=ROOT, capture_output=True, text=True, check=False, timeout=10,
        )
        self.assertEqual((completed.returncode, completed.stderr), (0, ""))
        self.assertEqual(json.loads(completed.stdout)["entries"], [])


if __name__ == "__main__":
    unittest.main()
