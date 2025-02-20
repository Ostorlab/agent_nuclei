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


# add unit test to ensure that when matched_at has path, it is removed
def testBuildVulnLocation_whenMatchedAtHasPath_returnsVulnLocation() -> None:
    """Ensure that when matched_at has a path, BuildVulnLocation returns a valid VulnLocation."""
    matched_at = "https://www.google.com/path/to/something"

    vuln_location = helpers.build_vuln_location(matched_at)

    assert vuln_location is not None
    domain_asset = vuln_location.asset
    assert isinstance(domain_asset, domain_name.DomainName)
    assert domain_asset.name == "www.google.com"


def testComputeDna_whenVulnerabilityTitleAndDomainName_returnsDna() -> None:
    """Ensure that when vulnerability_title and vuln_location is domain name, ComputeDna returns a valid DNA."""
    vulnerability_title = "Vulnerability Title Domain Name"
    matched_at = "https://www.google.com/path/to/something"
    vuln_location = helpers.build_vuln_location(matched_at)

    dna = helpers.compute_dna(vulnerability_title, vuln_location)

    assert dna is not None
    assert dna == "9d9334f22a089baf127931b9ffa512358531d961d160ddc3ba62e03e7b705400"


def testComputeDna_whenVulnerabilityTitleAndIpv4_returnsDna() -> None:
    """Ensure that when vulnerability_title and vuln_location is IPv4, ComputeDna returns a valid DNA."""
    vulnerability_title = "Vulnerability Title IPv4"
    matched_at = "https://70.70.70.70"
    vuln_location = helpers.build_vuln_location(matched_at)

    dna = helpers.compute_dna(vulnerability_title, vuln_location)

    assert dna is not None
    assert dna == "fd23df15dec3b9ec54f32b3ff5b46d11ad236c525eaf3e9ded85e913b3b356da"


def testComputeDna_whenVulnerabilityTitleAndIpv6_returnsDna() -> None:
    """Ensure that when vulnerability_title and vuln_location is IPv6, ComputeDna returns a valid DNA."""
    vulnerability_title = "Vulnerability Title IPv6"
    matched_at = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
    vuln_location = helpers.build_vuln_location(matched_at)

    dna = helpers.compute_dna(vulnerability_title, vuln_location)

    assert dna is not None
    assert dna == "eb5a5627d8627afa6c78b4e9f7d651a0411e717e9e0c3265dd0b903d91d38fe9"
