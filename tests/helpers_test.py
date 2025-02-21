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


def testBuildVulnLocation_whenMatchedAtIsDomainWithPath_returnsVulnLocationWithUrlMetadata() -> (
    None
):
    """Ensure that when matched_at is a domain with a path, build_vuln_location returns a valid VulnLocation with URL metadata."""
    matched_at = "https://www.google.com:443/path/to/something"

    vuln_location = helpers.build_vuln_location(matched_at)

    assert vuln_location is not None
    domain_asset = vuln_location.asset
    assert isinstance(domain_asset, domain_name.DomainName)
    assert domain_asset.name == "www.google.com"
    vuln_location_metadata = vuln_location.metadata
    assert len(vuln_location_metadata) == 2
    assert (
        any(
            metadata.metadata_type.name == "URL" and metadata.value == matched_at
            for metadata in vuln_location_metadata
        )
        is True
    )
    assert (
        any(
            metadata.metadata_type.name == "PORT" and metadata.value == "443"
            for metadata in vuln_location_metadata
        )
        is True
    )


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
    assert dna == "92b88517d093f9004fde3ec4141ff4a84714997f14629aa3c54db0c68feb3670"


def testComputeDna_whenVulnerabilityTitleAndIpv4_returnsDna() -> None:
    """Ensure that when vulnerability_title and vuln_location is IPv4, ComputeDna returns a valid DNA."""
    vulnerability_title = "Vulnerability Title IPv4"
    matched_at = "https://70.70.70.70"
    vuln_location = helpers.build_vuln_location(matched_at)

    dna = helpers.compute_dna(vulnerability_title, vuln_location)

    assert dna is not None
    assert dna == "ae6d70d5a43832443cd33050b9a1a3b99cd84ca6807b68a212c90e82f5287cf7"


def testComputeDna_whenVulnerabilityTitleAndIpv6_returnsDna() -> None:
    """Ensure that when vulnerability_title and vuln_location is IPv6, ComputeDna returns a valid DNA."""
    vulnerability_title = "Vulnerability Title IPv6"
    matched_at = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
    vuln_location = helpers.build_vuln_location(matched_at)

    dna = helpers.compute_dna(vulnerability_title, vuln_location)

    assert dna is not None
    assert dna == "465730e95c267b4ed4f2c6a23293affd93dd0bd9e0e1e20c60d119d47db8abe6"


def testComputeDna_whenSameDomainDifferentPaths_returnsDifferentDna() -> None:
    """Ensure that when the same domain with different paths, ComputeDna returns different DNA."""
    vulnerability_title = "Vulnerability Title Domain Name"
    matched_at_1 = "https://www.google.com/path/to/something"
    matched_at_2 = "https://www.google.com/another/path/to/something"
    vuln_location_1 = helpers.build_vuln_location(matched_at_1)
    vuln_location_2 = helpers.build_vuln_location(matched_at_2)

    dna_1 = helpers.compute_dna(vulnerability_title, vuln_location_1)
    dna_2 = helpers.compute_dna(vulnerability_title, vuln_location_2)

    assert dna_1 is not None
    assert dna_2 is not None
    assert dna_1 != dna_2


def testComputeDna_whenUnorderedDict_returnsConsistentDna() -> None:
    """Ensure that ComputeDna returns a consistent DNA when vuln_location dictionary keys are unordered."""
    vulnerability_title = "Vulnerability Title Unordered Dict"
    matched_at = "https://www.google.com:8080/path/to/something"
    vuln_location1 = helpers.build_vuln_location(matched_at)
    vuln_location2 = helpers.build_vuln_location(matched_at)

    assert vuln_location1 is not None
    assert vuln_location2 is not None

    vuln_location2.metadata = vuln_location2.metadata[::-1]

    dna1 = helpers.compute_dna(vulnerability_title, vuln_location1)
    dna2 = helpers.compute_dna(vulnerability_title, vuln_location2)

    assert dna1 is not None
    assert dna2 is not None
    assert dna1 == dna2
