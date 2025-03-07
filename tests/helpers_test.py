"""Unit tests for the helpers module."""

from typing import Any

from ostorlab.assets import domain_name
from ostorlab.assets import ipv4
from ostorlab.assets import ipv6
import pytest

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
    assert (
        dna
        == '{"location": {"domain_name": {"name": "www.google.com"}, "metadata": [{"type": "URL", "value": "https://www.google.com/path/to/something"}]}, "title": "Vulnerability Title Domain Name"}'
    )


def testComputeDna_whenVulnerabilityTitleAndIpv4_returnsDna() -> None:
    """Ensure that when vulnerability_title and vuln_location is IPv4, ComputeDna returns a valid DNA."""
    vulnerability_title = "Vulnerability Title IPv4"
    matched_at = "https://70.70.70.70"
    vuln_location = helpers.build_vuln_location(matched_at)

    dna = helpers.compute_dna(vulnerability_title, vuln_location)

    assert dna is not None
    assert (
        dna
        == '{"location": {"ipv4": {"host": "70.70.70.70", "mask": "32", "version": 4}, "metadata": []}, "title": "Vulnerability Title IPv4"}'
    )


def testComputeDna_whenVulnerabilityTitleAndIpv6_returnsDna() -> None:
    """Ensure that when vulnerability_title and vuln_location is IPv6, ComputeDna returns a valid DNA."""
    vulnerability_title = "Vulnerability Title IPv6"
    matched_at = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
    vuln_location = helpers.build_vuln_location(matched_at)

    dna = helpers.compute_dna(vulnerability_title, vuln_location)

    assert dna is not None
    assert (
        dna
        == '{"location": {"ipv6": {"host": "2001:0db8:85a3:0000:0000:8a2e:0370:7334", "mask": "128", "version": 6}, "metadata": []}, "title": "Vulnerability Title IPv6"}'
    )


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
    assert (
        dna_1
        == '{"location": {"domain_name": {"name": "www.google.com"}, "metadata": [{"type": "URL", "value": "https://www.google.com/path/to/something"}]}, "title": "Vulnerability Title Domain Name"}'
    )
    assert (
        dna_2
        == '{"location": {"domain_name": {"name": "www.google.com"}, "metadata": [{"type": "URL", "value": "https://www.google.com/another/path/to/something"}]}, "title": "Vulnerability Title Domain Name"}'
    )


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


@pytest.mark.parametrize(
    "unordered_dict, expected",
    [
        # Case: Dictionary keys are unordered
        ({"b": 2, "a": 1, "c": 3}, {"a": 1, "b": 2, "c": 3}),
        # Case: Nested dictionaries are also sorted
        ({"z": {"b": 2, "a": 1}, "y": 3}, {"y": 3, "z": {"a": 1, "b": 2}}),
        # Case: Lists inside dictionaries remain unchanged
        ({"list": [3, 1, 2], "key": "value"}, {"key": "value", "list": [1, 2, 3]}),
        # Case: Lists containing dictionaries get sorted by keys
        (
            {"list": [{"b": 2, "a": 1}, {"d": 4, "c": 3}]},
            {"list": [{"a": 1, "b": 2}, {"c": 3, "d": 4}]},
        ),
        # Case: Empty dictionary remains unchanged
        ({}, {}),
        # Case: Dictionary with single key remains unchanged
        ({"a": 1}, {"a": 1}),
    ],
)
def testSortDict_always_returnsSortedDict(
    unordered_dict: dict[str, Any], expected: dict[str, Any]
) -> None:
    """Ensure sort_dict correctly sorts dictionary keys recursively."""
    assert helpers.sort_dict(unordered_dict) == expected
