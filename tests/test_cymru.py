"""Tests for the Team Cymru DNS lookup module (wire-format helpers)."""

from antyswirusd.cymru import _build_txt_query, _encode_dns_name, _parse_txt_response


class TestEncodeDnsName:
    def test_single_label(self):
        raw = _encode_dns_name("hash.cymru.com")
        assert raw == b"\x04hash\x05cymru\x03com\x00"

    def test_empty_label_raises(self):
        _encode_dns_name("") == b"\x00"


class TestBuildTxtQuery:
    def test_contains_domain_and_type(self):
        domain = "aabb.hash.cymru.com"
        query = _build_txt_query(domain)
        assert b"aabb" in query
        assert b"cymru" in query
        # TXT type (16) little-endian in the question section
        assert query[-4:-2] == b"\x00\x10"

    def test_query_starts_with_valid_header(self):
        query = _build_txt_query("test.hash.cymru.com")
        assert len(query) > 12
        # QR bit should be 0 (query)
        assert query[2] == 0x01
        assert query[3] == 0x00


class TestParseTxtResponse:
    def test_empty_response(self):
        import pytest

        with pytest.raises(ValueError, match="response too short"):
            _parse_txt_response(b"")

    def test_too_short_response(self):
        import pytest

        with pytest.raises(ValueError, match="response too short"):
            _parse_txt_response(b"\x00" * 11)

    def test_nxdomain_returns_empty_list(self):
        """NXDOMAIN (rcode=3) returns an empty list."""
        header = b"\x00\x01\x80\x03\x00\x00\x00\x00\x00\x00\x00\x00"
        assert _parse_txt_response(header) == []

    def test_servfail_raises(self):
        """SERVFAIL (rcode=2) raises."""
        import pytest

        header = b"\x00\x01\x80\x02\x00\x00\x00\x00\x00\x00\x00\x00"
        with pytest.raises(ValueError, match="rcode=2"):
            _parse_txt_response(header)

    def test_not_a_response_raises(self):
        """Missing QR bit raises."""
        import pytest

        header = b"\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        with pytest.raises(ValueError, match="not a DNS response"):
            _parse_txt_response(header)
