"""Unit tests for the VPN configuration."""

from pytest_mock import plugin

from agent.vpn import wg_vpn


def testVpnConnectionCommands_always_shouldRunCorrectCommands(
    mocker: plugin.MockerFixture,
) -> None:
    """Ensure the VPN configuration commands follow the correct syntax."""

    vpn_conf = """[Interface]
        PrivateKey = dummyPrivateKey
        Address = 0.0.0.0/32
        DNS = 8.8.8.8

        [Peer]
        PublicKey = dummyPublicKey
        AllowedIPs = 0.0.0.0/32
        Endpoint = 42.42.42.42
    """
    dns_conf = """nameserver 8.8.8.8"""

    write_configs_mock = mocker.patch("pathlib.Path.write_text")
    subprocess_mock = mocker.patch("subprocess.run")

    wg_vpn.enable_vpn_connection(vpn_config=vpn_conf, dns_config=dns_conf)

    assert write_configs_mock.call_args_list[0].kwargs["data"] == vpn_conf
    assert write_configs_mock.call_args_list[1].kwargs["data"] == dns_conf
    assert (
        " ".join(subprocess_mock.call_args_list[0].kwargs["args"]) == "wg-quick up wg0"
    )
