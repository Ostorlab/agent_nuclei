"""Helper for nuclei Agent to complete the scan."""
import ipaddress
import logging
from typing import Tuple, cast, Optional
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


def split_ipv4(potential_ip: str) -> Tuple[str, str | None]:
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
) -> Optional[agent_report_vulnerability_mixin.VulnerabilityLocation]:
    """Build VulnerabilityLocation based on the asset.

    Args:
        matched_at: string.

    Returns:
        - VulnerabilityLocation.
    """
    if matched_at is None or matched_at == "":
        logger.info("Matched at value is absent.")
        return None
    metadata = []
    target = parse.urlparse(matched_at)
    asset: ipv4_asset.IPv4 | ipv6_asset.IPv6 | domain_asset.DomainName
    ip = None
    port = None
    if is_ipv4(matched_at) is True:
        ip, port = split_ipv4(matched_at)
        asset = ipv4_asset.IPv4(host=str(ip), version=4, mask="32")
    elif is_ipv6(matched_at) is not False:
        ip = matched_at
        asset = ipv6_asset.IPv6(host=str(ip), version=4, mask="128")
    else:
        asset = domain_asset.DomainName(name=prepare_domain_asset(matched_at))

    if target.port is not None or (ip is not None and port is not None):
        metadata_type = agent_report_vulnerability_mixin.MetadataType.PORT
        metadata_value = str(target.port) if target.port is not None else port
        assert metadata_value is not None
        metadata = [
            agent_report_vulnerability_mixin.VulnerabilityLocationMetadata(
                metadata_type=metadata_type, value=metadata_value
            )
        ]
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
