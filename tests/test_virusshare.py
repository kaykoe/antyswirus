"""Tests for the VirusShare sync module (parser helpers)."""

from __future__ import annotations

import io
import zipfile

from antyswirusd.virusshare import _extract_hashes


class TestExtractHashes:
    def test_extracts_hashes_from_zip(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr(
                "VirusShare_00000.txt",
                "a" * 64 + "\n" + "b" * 64 + "\n" + "c" * 64 + "\n",
            )
        buf.seek(0)
        hashes = _extract_hashes(buf.read())
        assert hashes == ["a" * 64, "b" * 64, "c" * 64]

    def test_skips_empty_lines(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr(
                "hashes.txt",
                "a" * 64 + "\n\n\n" + "b" * 64 + "\n",
            )
        buf.seek(0)
        hashes = _extract_hashes(buf.read())
        assert hashes == ["a" * 64, "b" * 64]

    def test_strips_whitespace(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr(
                "hashes.txt",
                "  " + "a" * 64 + "  \n" + "b" * 64 + "\n",
            )
        buf.seek(0)
        hashes = _extract_hashes(buf.read())
        assert hashes == ["a" * 64, "b" * 64]

    def test_multiple_files_in_zip(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("file1.txt", "a" * 64 + "\n")
            zf.writestr("file2.txt", "b" * 64 + "\n")
        buf.seek(0)
        hashes = _extract_hashes(buf.read())
        assert "a" * 64 in hashes
        assert "b" * 64 in hashes

    def test_empty_zip(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("empty.txt", "")
        buf.seek(0)
        hashes = _extract_hashes(buf.read())
        assert hashes == []
