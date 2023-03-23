"""Enable VPN connection through wireguard."""
import pathlib
import subprocess
import logging


logger = logging.getLogger(__name__)
WG_CONF_DEFAULT_PATH = "/etc/wireguard/wg0.conf"
DNS_CONFIG_PATH = "/etc/resolv.conf"


def enable_vpn_connection(vpn_config: str | None, dns_config: str | None) -> None:
    """Enable a VPN connection through wireguard.
    Args:
        vpn_config: Content of the VPN:wg0.conf configuration file.
        dns_config: Content of the /etc/resolv.conf file.

    Returns:
        None
    """
    if vpn_config is None or dns_config is None:
        return

    _set_vpn_config_file(vpn_config)
    _start_wg()
    _set_wg_dns_config(dns_config)
    logger.info("VPN connection established.")


def _set_vpn_config_file(vpn_config: str) -> None:
    """Set the country configuration file as main one in wireguard."""
    wg_config_path = pathlib.Path(WG_CONF_DEFAULT_PATH)
    wg_config_path.write_text(data=vpn_config)


def _start_wg() -> None:
    """Start wireguard"""
    command = ["wg-quick", "up", "wg0"]
    p = subprocess.run(args=command, capture_output=True, check=True)
    stdout, stderr = p.stdout, p.stderr
    logger.info("Stdout: %s", stdout.decode())
    if stderr != b"":
        logger.error("Stderr: %s", stderr.decode())


def _set_wg_dns_config(dns_config: str) -> None:
    """Set wireguard DNS configuration file."""
    dns_config_path = pathlib.Path(DNS_CONFIG_PATH)
    dns_config_path.write_text(data=dns_config)
