"""Run with python -m examples.compare_synthetic from the repository.

Create two small ZIP fixtures in a temporary directory, compare their directory
metadata, print JSON, and remove the fixtures. No archive members are extracted.
The fixture creator writes synthetic payloads; compare_zips never reads them.
"""

import json
from pathlib import Path
import tempfile
import warnings
import zipfile

from zip_manifest_audit import compare_zips


def _create(path, members):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(path, mode="x") as archive:
            for name, contents in members:
                info = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
                archive.writestr(info, contents)


def main():
    with tempfile.TemporaryDirectory(prefix="zip-comparison-example-") as directory:
        before = Path(directory) / "before.zip"
        after = Path(directory) / "after.zip"
        _create(before, [
            ("docs/readme.txt", b"Version one.\n"),
            ("retired.txt", b"Removed in version two.\n"),
            ("duplicate.txt", b"First occurrence stays.\n"),
            ("duplicate.txt", b"Second occurrence before.\n"),
        ])
        _create(after, [
            ("duplicate.txt", b"First occurrence stays.\n"),
            ("docs/readme.txt", b"Version two.\n"),
            ("new.txt", b"Added in version two.\n"),
            ("duplicate.txt", b"Second occurrence after.\n"),
        ])
        print(json.dumps(compare_zips(before, after), ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()
