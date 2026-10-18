"""Tests for :mod:`winbindex.symbol_server`."""

from __future__ import annotations

import pytest
from winbindex.symbol_server import (
    DEFAULT_SYMBOL_SERVER_URL,
    build_pdb_url,
    normalize_guid,
    build_binary_url,
)

# ---------------------------------------------------------------- normalize_guid


class TestNormalizeGuid:
    def test_dashed_guid(self):
        assert normalize_guid("1B72224D-37B8-1792-2820-0ED8994498B2") == "1B72224D37B8179228200ED8994498B2"

    def test_undashed_guid(self):
        assert normalize_guid("1b72224d37b8179228200ed8994498b2") == "1B72224D37B8179228200ED8994498B2"

    def test_lowercase_dashed(self):
        assert normalize_guid("1b72224d-37b8-1792-2820-0ed8994498b2") == "1B72224D37B8179228200ED8994498B2"

    @pytest.mark.parametrize(
        "bad",
        [
            "",
            "not-a-guid",
            "1B72224D37B8179228200ED8994498",  # too short
            "1B72224D37B8179228200ED8994498B2EXTRA",  # too long
            "ZZZZZZZZ-37B8-1792-2820-0ED8994498B2",  # non-hex
        ],
    )
    def test_invalid_raises(self, bad):
        with pytest.raises(ValueError):
            normalize_guid(bad)


# --------------------------------------------------------------- build_binary_url


class TestBuildBinaryUrl:
    def test_blog_post_example(self):
        # Example from the original blog post:
        # srv2.sys with timestamp 0xEE8E2F4F and image size 0xc7000.
        url = build_binary_url("srv2.sys", 0xEE8E2F4F, 0xC7000)
        assert url == "https://msdl.microsoft.com/download/symbols/srv2.sys/EE8E2F4Fc7000/srv2.sys"

    def test_p2pgraph_example(self):
        # timestamp=2538600830 (0x974FF97E), virtualSize=380928 (0x5d000)
        url = build_binary_url("p2pgraph.dll", 2538600830, 380928)
        assert url == "https://msdl.microsoft.com/download/symbols/p2pgraph.dll/974FF97E5d000/p2pgraph.dll"

    def test_ntdll_example(self):
        # ntdll.dll, timestamp=0xB7E2D60A (3085096458), virtualSize=0x213000 (2174976)
        url = build_binary_url("ntdll.dll", 0xB7E2D60A, 0x213000)
        assert url == "https://msdl.microsoft.com/download/symbols/ntdll.dll/B7E2D60A213000/ntdll.dll"

    def test_uses_default_base_url(self):
        url = build_binary_url("foo.dll", 1, 1)
        assert url.startswith(DEFAULT_SYMBOL_SERVER_URL + "/")

    def test_custom_base_url(self):
        url = build_binary_url("foo.dll", 0xDEAD, 0xBEEF, base_url="http://mirror.example/")
        assert url == "http://mirror.example/foo.dll/0000DEADbeef/foo.dll"

    def test_zero_timestamp_is_padded(self):
        url = build_binary_url("foo.dll", 0, 0x1000)
        assert "/00000000" in url
        # The trailing image size should be lowercase, no padding.
        assert url.endswith("/000000001000/foo.dll")

    @pytest.mark.parametrize(
        "args",
        [
            ("", 1, 1),
            ("foo.dll", -1, 1),
            ("foo.dll", 1, -1),
        ],
    )
    def test_invalid_raises(self, args):
        with pytest.raises(ValueError):
            build_binary_url(*args)


# ------------------------------------------------------------------ build_pdb_url


class TestBuildPdbUrl:
    def test_kernel32_pdb_example(self):
        url = build_pdb_url("kernel32.pdb", "1B72224D-37B8-1792-2820-0ED8994498B2", 1)
        assert (
            url
            == "https://msdl.microsoft.com/download/symbols/kernel32.pdb/1B72224D37B8179228200ED8994498B21/kernel32.pdb"
        )

    def test_netbios_pdb_example(self):
        # From the pdbfetch README.
        url = build_pdb_url("netbios.pdb", "109096de-2cf2-44bd-8d03-0e5473c5253a", 1)
        assert (
            url
            == "https://msdl.microsoft.com/download/symbols/netbios.pdb/109096DE2CF244BD8D030E5473C5253A1/netbios.pdb"
        )

    def test_age_uses_uppercase_hex(self):
        url = build_pdb_url("foo.pdb", "0" * 32, 0xA)
        assert url.endswith("0000000000000000000000000000000A/foo.pdb")

    def test_undashed_guid_works(self):
        url = build_pdb_url("foo.pdb", "0123456789ABCDEF0123456789ABCDEF", 2)
        assert "0123456789ABCDEF0123456789ABCDEF2" in url

    @pytest.mark.parametrize(
        "args",
        [
            ("", "0" * 32, 1),
            ("foo.pdb", "not-a-guid", 1),
            ("foo.pdb", "0" * 32, -1),
        ],
    )
    def test_invalid_raises(self, args):
        with pytest.raises(ValueError):
            build_pdb_url(*args)

    def test_custom_base_url(self):
        url = build_pdb_url("foo.pdb", "0" * 32, 1, base_url="https://mirror.example/symbols")
        assert url.startswith("https://mirror.example/symbols/")
