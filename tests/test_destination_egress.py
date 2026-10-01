from __future__ import annotations

import pytest

from agent_containment.destination_egress import (
    canonical_destination_strings,
    canonicalize_destinations,
    parse_destination,
)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("api.EXAMPLE.com:443", "api.example.com:443"),
        ("api.example.com.:443", "api.example.com:443"),
        ("192.0.2.10:443", "192.0.2.10:443"),
        ("2001:db8::10", "2001:db8::10"),
    ],
)
def test_parse_destination(value, expected):
    if ":" not in value or value.count(":") > 1:
        if value == "2001:db8::10":
            pytest.raises(ValueError, parse_destination, value)
            return
    assert parse_destination(value).host == expected.split(":")[0]


def test_ipv6_requires_brackets():
    with pytest.raises(ValueError, match="IPv6"):
        parse_destination("2001:db8::10:443")


def test_ipv6_canonicalization():
    assert canonical_destination_strings(["[2001:0DB8::10]:443"]) == ("[2001:db8::10]:443",)


def test_canonicalize_deduplicates_and_sorts():
    assert canonical_destination_strings(
        ["Z.example.com:443", "a.example.com:53", "z.example.com:443"]
    ) == ("a.example.com:53", "z.example.com:443")


@pytest.mark.parametrize(
    "value",
    [
        "",
        "api.example.com",
        "api.example.com:0",
        "api.example.com:65536",
        "api.example.com:https",
        "api.example.com:443 ",
        "api_example.com:443",
        "*.example.com:443",
        "10.0.0.0/8:443",
        "https://api.example.com:443",
        "api.example.com:443/path",
    ],
)
def test_parse_destination_rejects_unsupported_or_malformed(value):
    with pytest.raises(ValueError):
        parse_destination(value)
