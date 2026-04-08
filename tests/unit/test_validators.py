from __future__ import annotations

import pytest

from cuttix.utils.validators import (
    is_valid_cidr,
    is_valid_ip,
    is_valid_mac,
    is_valid_port,
    normalize_mac,
    parse_port_range,
)


class TestIPValidation:
    def test_valid_ips(self):
        assert is_valid_ip("192.168.1.1")
        assert is_valid_ip("10.0.0.1")
        assert is_valid_ip("255.255.255.255")

    def test_invalid_ips(self):
        assert not is_valid_ip("999.1.1.1")
        assert not is_valid_ip("not_an_ip")
        assert not is_valid_ip("")
        assert not is_valid_ip("192.168.1")


class TestCIDRValidation:
    def test_valid_cidrs(self):
        assert is_valid_cidr("192.168.1.0/24")
        assert is_valid_cidr("10.0.0.0/8")

    def test_invalid_cidrs(self):
        assert not is_valid_cidr("garbage")
        assert not is_valid_cidr("192.168.1.0/33")


class TestMACValidation:
    def test_valid_macs(self):
        assert is_valid_mac("aa:bb:cc:dd:ee:ff")
        assert is_valid_mac("AA:BB:CC:DD:EE:FF")
        assert is_valid_mac("aa-bb-cc-dd-ee-ff")

    def test_invalid_macs(self):
        assert not is_valid_mac("not_a_mac")
        assert not is_valid_mac("aa:bb:cc")
        assert not is_valid_mac("")


class TestNormalizeMAC:
    def test_lowercase_colon(self):
        assert normalize_mac("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"
        assert normalize_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"


class TestPortValidation:
    def test_valid_ports(self):
        assert is_valid_port(1)
        assert is_valid_port(80)
        assert is_valid_port(65535)

    def test_invalid_ports(self):
        assert not is_valid_port(0)
        assert not is_valid_port(65536)
        assert not is_valid_port(-1)


class TestPortRangeParsing:
    def test_single_port(self):
        assert parse_port_range("80") == [80]

    def test_comma_separated(self):
        assert parse_port_range("80,443,8080") == [80, 443, 8080]

    def test_range(self):
        result = parse_port_range("80-83")
        assert result == [80, 81, 82, 83]

    def test_mixed(self):
        result = parse_port_range("22,80-82,443")
        assert result == [22, 80, 81, 82, 443]

    def test_invalid_range_raises(self):
        with pytest.raises(ValueError):
            parse_port_range("0")

    def test_reversed_range_raises(self):
        with pytest.raises(ValueError):
            parse_port_range("100-50")
