"""Helper for nuclei Agent to complete the scan."""

import collections.abc
import ipaddress
import json
import logging
import re
from typing import Any, cast
from urllib import parse

import tld
from ostorlab.agent.mixins import agent_report_vulnerability_mixin
from ostorlab.assets import domain_name as domain_asset
from ostorlab.assets import ipv4 as ipv4_asset
from ostorlab.assets import ipv6 as ipv6_asset
from rich import logging as rich_logging

logging.basicConfig(
    format="%(message)s",
    datefmt="[%X]",
    handlers=[rich_logging.RichHandler(rich_tracebacks=True)],
    level="INFO",
    force=True,
)
logger = logging.getLogger(__name__)


# Lowercased `Server` header tokens identifying CDN/WAF/edge-proxy products
# that serve their own responses on behalf of an origin. A finding served by
# one of these cannot be attributed to an on-prem appliance CVE.
CDN_SERVER_TOKENS: tuple[str, ...] = (
    "cloudflare",
    "akamai",
    "incapsula",
    "sucuri",
    "imperva",
    "fastly",
    "cloudfront",
    "awselb",
    "varnish",
    "envoy",
)

# Lowercased product-family keywords for on-prem/network appliance products
# whose CVEs cannot legitimately be served behind a CDN/WAF.
ON_PREM_PRODUCT_TOKENS: tuple[str, ...] = (
    "fortios",
    "fortinet",
    "cisco",
    "juniper",
    "junos",
    "paloalto",
    "pan-os",
    "sonicwall",
    "sophos",
    "watchguard",
    "hillstone",
    "checkpoint",
    "check point",
)

_SERVER_HEADER_RE = re.compile(r"(?im)^server:\s*(.+)$")


def extract_server_header(response: str | None) -> str | None:
    """Extract the value of the ``Server`` HTTP header from a raw response.

    Args:
        response: The raw HTTP response captured by nuclei, or ``None``.

    Returns:
        The ``Server`` header value (stripped), or ``None`` when absent.
    """
    if not response:
        return None
    match = _SERVER_HEADER_RE.search(response)
    if match is None:
        return None
    return match.group(1).strip()


def is_product_fingerprint_mismatch(
    nuclei_data: collections.abc.Mapping[str, Any],
) -> bool:
    """Detect when a finding's CVE attribution conflicts with the served product.

    A nuclei template can match on generic behaviour (e.g. an open redirect)
    while attributing the finding to a specific on-prem appliance product via
    its CVE/CPE. When the captured response is served by a CDN/WAF, that
    product attribution is fabricated.

    Args:
        nuclei_data: A single nuclei finding dictionary.

    Returns:
        ``True`` when the response is served by a known CDN/WAF while the
        template attributes the finding to an on-prem appliance product.
    """
    server = extract_server_header(nuclei_data.get("response"))
    if server is None:
        return False
    server_lower = server.lower()
    if not any(token in server_lower for token in CDN_SERVER_TOKENS):
        return False
    info = nuclei_data.get("info") or {}
    attributed_parts: list[str] = [str(info.get("name", ""))]
    attributed_parts.extend(str(tag) for tag in info.get("tags") or [])
    matched_at = nuclei_data.get("matched-at")
    if matched_at is not None:
        attributed_parts.append(str(matched_at))
    attributed_text = " ".join(attributed_parts).lower()
    return any(token in attributed_text for token in ON_PREM_PRODUCT_TOKENS)


def is_ipv4(potential_ip: str) -> bool:
    """check if the potential_ip is a valid ipv4.

    Args:
        potential_ip: string.

    Returns:
        - boolean.
    """
    ip, _ = split_ipv4(potential_ip)
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ValueError:
        return False


def split_ipv4(potential_ip: str) -> tuple[str, str | None]:
    """split the potential_ip to get the ip and the port if existed.

    Args:
        potential_ip: string.

    Returns:
        - ip, port.
    """
    ip = potential_ip
    port = None
    if ":" in potential_ip:
        ip, port = potential_ip.split(":", maxsplit=1)
    return ip, port


def is_ipv6(potential_ip: str) -> bool:
    """check if the potential_ip is a valid ipv6.

    Args:
        potential_ip: string.

    Returns:
        - boolean.
    """
    try:
        ipaddress.IPv6Address(potential_ip)
        return True
    except ValueError:
        return False


def build_vuln_location(
    matched_at: str,
) -> agent_report_vulnerability_mixin.VulnerabilityLocation | None:
    """Build VulnerabilityLocation based on the asset.

    Args:
        matched_at: string.

    Returns:
        - VulnerabilityLocation.
    """
    if matched_at is None or matched_at == "":
        logger.debug("Matched at value is absent.")
        return None
    metadata = []
    target = parse.urlparse(matched_at)
    asset: ipv4_asset.IPv4 | ipv6_asset.IPv6 | domain_asset.DomainName
    ip = None
    port = None
    potential_ip = matched_at
    if target.scheme != "":
        potential_ip = potential_ip.replace(f"{target.scheme}://", "")
    if is_ipv4(potential_ip) is True:
        ip, port = split_ipv4(potential_ip)
        asset = ipv4_asset.IPv4(host=str(ip), version=4, mask="32")
    elif is_ipv6(potential_ip) is True:
        asset = ipv6_asset.IPv6(host=str(potential_ip), version=6, mask="128")
    else:
        full_url = parse.urlunparse(
            (target.scheme, target.netloc, target.path, "", "", "")
        )
        metadata.append(
            agent_report_vulnerability_mixin.VulnerabilityLocationMetadata(
                metadata_type=agent_report_vulnerability_mixin.MetadataType.URL,
                value=full_url,
            )
        )
        asset = domain_asset.DomainName(name=prepare_domain_asset(matched_at))

    if target.port is not None or (ip is not None and port is not None):
        metadata_type = agent_report_vulnerability_mixin.MetadataType.PORT
        metadata_value = str(target.port) if target.port is not None else port
        if metadata_value is not None:
            metadata.append(
                agent_report_vulnerability_mixin.VulnerabilityLocationMetadata(
                    metadata_type=metadata_type, value=metadata_value
                )
            )

    return agent_report_vulnerability_mixin.VulnerabilityLocation(
        asset=asset, metadata=metadata
    )


def prepare_domain_asset(url: str) -> str:
    """Prepares the domain asset object for the given URL.

    Args:
    url: The URL to extract the domain from.

    Returns:
    Optional[domain_asset.DomainName]: A domain asset
    """
    if url is None:
        return ""

    canonized_domain = tld.get_tld(
        url, as_object=True, fix_protocol=True, fail_silently=True
    )

    if canonized_domain is None:
        return parse.urlparse(url).netloc

    tld_domain = cast(tld.Result, canonized_domain)
    result_neloc = tld_domain.parsed_url.netloc
    if ":" in result_neloc:
        asset = result_neloc.split(":")[0]
    else:
        asset = result_neloc

    return asset


def sort_dict(d: dict[str, Any] | list[Any]) -> dict[str, Any] | list[Any]:
    """Recursively sort dictionary keys and lists within.

    Args:
        d: The dictionary or list to sort.

    Returns:
        A sorted dictionary or list.
    """
    if isinstance(d, dict):
        return {k: sort_dict(v) for k, v in sorted(d.items())}
    if isinstance(d, list):
        return sorted(
            d,
            key=lambda x: (
                json.dumps(x, sort_keys=True) if isinstance(x, dict) else str(x)
            ),
        )
    return d


def compute_dna(
    vulnerability_title: str,
    vuln_location: agent_report_vulnerability_mixin.VulnerabilityLocation | None,
) -> str:
    """Compute a deterministic, debuggable DNA representation for a vulnerability.

    Args:
        vulnerability_title: The title of the vulnerability.
        vuln_location: The location of the vulnerability.

    Returns:
        A deterministic JSON representation of the vulnerability DNA.
    """
    dna_data: dict[str, Any] = {"title": vulnerability_title}

    if vuln_location is not None:
        location_dict: dict[str, Any] = vuln_location.to_dict()
        sorted_location_dict = sort_dict(location_dict)
        dna_data["location"] = sorted_location_dict

    return json.dumps(dna_data, sort_keys=True)
