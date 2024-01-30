"""Unit tests for the helpers module."""

from ostorlab.assets import domain_name
from ostorlab.assets import ipv4
from ostorlab.assets import ipv6

from agent import helpers


def testBuildVulnLocation_whenMatchedAtIsIpv4_returnsVulnLocation() -> None:
    """Ensure that when matched_at is an IPv4, BuildVulnLocation returns a valid VulnLocation."""
    matched_at = "70.70.70.70:443"

    vuln_location = helpers.build_vuln_location(matched_at)

    assert vuln_location is not None
    ipv4_asset = vuln_location.asset
    assert isinstance(ipv4_asset, ipv4.IPv4)
    assert ipv4_asset.host == "70.70.70.70"
    assert ipv4_asset.version == 4
    assert ipv4_asset.mask == "32"


def testBuildVulnLocation_whenMatchedAtIsIpv6_returnsVulnLocation() -> None:
    """Ensure that when matched_at is an IPv6, BuildVulnLocation returns a valid VulnLocation."""
    matched_at = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"

    vuln_location = helpers.build_vuln_location(matched_at)

    assert vuln_location is not None
    ipv6_asset = vuln_location.asset
    assert isinstance(ipv6_asset, ipv6.IPv6)
    assert ipv6_asset.host == "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
    assert ipv6_asset.version == 6
    assert ipv6_asset.mask == "128"


def testBuildVulnLocation_whenMatchedAtIsDomain_returnsVulnLocation() -> None:
    """Ensure that when matched_at is a domain, BuildVulnLocation returns a valid VulnLocation."""
    matched_at = "https://www.google.com"

    vuln_location = helpers.build_vuln_location(matched_at)

    assert vuln_location is not None
    domain_asset = vuln_location.asset
    assert isinstance(domain_asset, domain_name.DomainName)
    assert domain_asset.name == "www.google.com"


def testBuildVulnLocation_whenMatchedAtIsIpv4WithScheme_returnsValidVulnLocation() -> (
    None
):
    """Ensure that when a scheme is present, BuildVulnLocation returns a valid VulnLocation."""
    matched_at = "https://70.70.70.70"

    vuln_location = helpers.build_vuln_location(matched_at)

    assert vuln_location is not None
    ipv4_asset = vuln_location.asset
    assert isinstance(ipv4_asset, ipv4.IPv4)
    assert ipv4_asset.host == "70.70.70.70"
    assert ipv4_asset.version == 4
    assert ipv4_asset.mask == "32"
