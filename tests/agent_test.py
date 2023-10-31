"""Unittests for nuclei class."""
import subprocess
from typing import Dict
from typing import List
from unittest import mock

import pytest
import requests_mock as rq_mock
from ostorlab.agent.message import message
from ostorlab.agent.mixins import agent_report_vulnerability_mixin
from pytest_mock import plugin

from agent import agent_nuclei
from agent import helpers


@mock.patch("agent.agent_nuclei.OUTPUT_PATH", "./tests/result_nuclei.json")
def testAgentNuclei_whenBinaryAvailable_RunScan(
    scan_message: message.Message,
    nuclei_agent_no_url_scope: agent_nuclei.AgentNuclei,
    agent_persist_mock: Dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
) -> None:
    """Tests running the agent and parsing the json output."""
    mocker.patch("subprocess.run", return_value=None)
    mock_report_vulnerability = mocker.patch(
        "agent.agent_nuclei.AgentNuclei.report_vulnerability", return_value=None
    )
    nuclei_agent_no_url_scope.process(scan_message)
    mock_report_vulnerability.assert_called_once()
    assert (
        mock_report_vulnerability.call_args.kwargs["entry"].cvss_v3_vector
        == "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
    )
    assert (
        """Matched : `ats` at"""
        in mock_report_vulnerability.call_args.kwargs["technical_detail"]
    )
    assert (
        "Author" not in mock_report_vulnerability.call_args.kwargs["technical_detail"]
    )
    assert (
        mock_report_vulnerability.call_args.kwargs["risk_rating"]
        == agent_report_vulnerability_mixin.RiskRating.INFO
    )


@mock.patch("agent.agent_nuclei.OUTPUT_PATH", "./tests/result_nuclei.json")
def testAgentNuclei_whenUrlTemplatesGiven_RunScan(
    requests_mock: rq_mock.mocker.Mocker,
    scan_message: message.Message,
    nuclei_agent_args: agent_nuclei.AgentNuclei,
    agent_persist_mock: Dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
) -> None:
    """Tests running the agent and parsing the json output."""
    run_command_mock = mocker.patch("subprocess.run", return_value=None)
    mocker.patch("os.path.exists", return_value=True)
    requests_mock.get(
        "https://raw.githubusercontent.com/Ostorlab/main/templates/CVE1.yaml",
        content=b"test1",
    )
    requests_mock.get(
        "https://raw.githubusercontent.com/Ostorlab/main/templates/CVE2.yaml",
        content=b"test2",
    )
    mock_report_vulnerability = mocker.patch(
        "agent.agent_nuclei.AgentNuclei.report_vulnerability", return_value=None
    )
    nuclei_agent_args.process(scan_message)

    run_command_mock.assert_called()
    run_command_args = run_command_mock.call_args_list
    assert run_command_args[1][0][0] == [
        "/nuclei/nuclei",
        "-u",
        "209.235.136.112",
        "-j",
        "-irr",
        "-silent",
        "-o",
        "./tests/result_nuclei.json",
    ]

    assert run_command_args[0].args == (
        [
            "/nuclei/nuclei",
            "-u",
            "209.235.136.112",
            "-j",
            "-irr",
            "-silent",
            "-o",
            "./tests/result_nuclei.json",
            "-t",
            "CVE1.yaml",
            "-t",
            "CVE2.yaml",
        ],
    )
    mock_report_vulnerability.assert_called()


@mock.patch("agent.agent_nuclei.OUTPUT_PATH", "./tests/result_nuclei.json")
def testAgentNuclei_whenLinkMessageGiven_NotScan(
    scan_message_link_2: message.Message,
    nuclei_agent: agent_nuclei.AgentNuclei,
    agent_persist_mock: Dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
) -> None:
    """Tests running the agent and parsing the json output."""
    run_command_mock = mocker.patch("subprocess.run", return_value=None)
    mocker.patch("os.path.exists", return_value=True)
    nuclei_agent.process(scan_message_link_2)
    run_command_mock.assert_not_called()


@mock.patch("agent.agent_nuclei.OUTPUT_PATH", "./tests/result_nuclei.json")
def testAgentNuclei_whenDomainNameGiven_NotScan(
    scan_message_domain_2: message.Message,
    nuclei_agent: agent_nuclei.AgentNuclei,
    agent_persist_mock: Dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
) -> None:
    """Tests running the agent and parsing the json output."""
    run_command_mock = mocker.patch("subprocess.run", return_value=None)
    mocker.patch("os.path.exists", return_value=True)
    nuclei_agent.process(scan_message_domain_2)
    run_command_mock.assert_not_called()


@mock.patch("agent.agent_nuclei.OUTPUT_PATH", "./tests/result_nuclei.json")
def testAgentNuclei_whenTemplatesProvided_scansAppWithTemplate(
    requests_mock: rq_mock.mocker.Mocker,
    scan_message: message.Message,
    nuclei_agent_args: agent_nuclei.AgentNuclei,
    agent_persist_mock: Dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
) -> None:
    """Tests running the agent and parsing the json output."""
    run_command_mock = mocker.patch("subprocess.run", return_value=None)
    mocker.patch("os.path.exists", return_value=True)
    requests_mock.get(
        "https://raw.githubusercontent.com/Ostorlab/main/templates/CVE1.yaml",
        content=b"test1",
    )
    requests_mock.get(
        "https://raw.githubusercontent.com/Ostorlab/main/templates/CVE2.yaml",
        content=b"test2",
    )
    mocker.patch(
        "agent.agent_nuclei.AgentNuclei.report_vulnerability", return_value=None
    )
    nuclei_agent_args.process(scan_message)
    run_command_mock.assert_called()
    run_command_args = run_command_mock.call_args_list
    assert run_command_args[0].args == (
        [
            "/nuclei/nuclei",
            "-u",
            "209.235.136.112",
            "-j",
            "-irr",
            "-silent",
            "-o",
            "./tests/result_nuclei.json",
            "-t",
            "CVE1.yaml",
            "-t",
            "CVE2.yaml",
        ],
    )
    assert run_command_args[1].args == (
        [
            "/nuclei/nuclei",
            "-u",
            "209.235.136.112",
            "-j",
            "-irr",
            "-silent",
            "-o",
            "./tests/result_nuclei.json",
        ],
    )


@mock.patch("agent.agent_nuclei.OUTPUT_PATH", "./tests/result_nuclei.json")
def testAgentNuclei_whenMessageIsIpRange_scanMultipleTargets(
    requests_mock: rq_mock.mocker.Mocker,
    scan_message_network_range: message.Message,
    nuclei_agent_no_url_scope: agent_nuclei.AgentNuclei,
    agent_persist_mock: Dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
) -> None:
    """Tests running the agent and parsing the json output."""
    run_command_mock = mocker.patch("subprocess.run", return_value=None)
    mocker.patch("os.path.exists", return_value=True)
    requests_mock.get(
        "https://raw.githubusercontent.com/Ostorlab/main/templates/CVE1.yaml",
        content=b"test1",
    )
    requests_mock.get(
        "https://raw.githubusercontent.com/Ostorlab/main/templates/CVE2.yaml",
        content=b"test2",
    )
    mocker.patch(
        "agent.agent_nuclei.AgentNuclei.report_vulnerability", return_value=None
    )
    nuclei_agent_no_url_scope.process(scan_message_network_range)
    run_command_mock.assert_called()
    run_command_args = run_command_mock.call_args_list
    assert "209.235.136.113" in run_command_args[0].args[0]
    assert "209.235.136.121" in run_command_args[0].args[0]


@mock.patch("agent.agent_nuclei.OUTPUT_PATH", "./tests/result_nuclei.json")
def testAgentNuclei_whenMessageIsDomain_scanMultipleTargets(
    requests_mock: rq_mock.mocker.Mocker,
    scan_message_domain: message.Message,
    nuclei_agent: agent_nuclei.AgentNuclei,
    agent_persist_mock: Dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
) -> None:
    """Tests running the agent and parsing the json output."""
    run_command_mock = mocker.patch("subprocess.run", return_value=None)
    mocker.patch("os.path.exists", return_value=True)
    requests_mock.get(
        "https://raw.githubusercontent.com/Ostorlab/main/templates/CVE1.yaml",
        content=b"test1",
    )
    requests_mock.get(
        "https://raw.githubusercontent.com/Ostorlab/main/templates/CVE2.yaml",
        content=b"test2",
    )
    mocker.patch(
        "agent.agent_nuclei.AgentNuclei.report_vulnerability", return_value=None
    )
    nuclei_agent.process(scan_message_domain)
    run_command_mock.assert_called()
    run_command_args = run_command_mock.call_args_list
    assert "https://apple.com" in run_command_args[0].args[0]


@mock.patch("agent.agent_nuclei.OUTPUT_PATH", "./tests/result_nuclei.json")
def testAgentNuclei_whenMessageIsLargeIpRange_scanMultipleTargets(
    requests_mock: rq_mock.mocker.Mocker,
    scan_message_large_network_range: message.Message,
    nuclei_agent_no_url_scope: agent_nuclei.AgentNuclei,
    agent_persist_mock: Dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
) -> None:
    """Tests running the agent and parsing the json output."""
    run_command_mock = mocker.patch("subprocess.run", return_value=None)
    mocker.patch("os.path.exists", return_value=True)
    requests_mock.get(
        "https://raw.githubusercontent.com/Ostorlab/main/templates/CVE1.yaml",
        content=b"test1",
    )
    requests_mock.get(
        "https://raw.githubusercontent.com/Ostorlab/main/templates/CVE2.yaml",
        content=b"test2",
    )
    mocker.patch(
        "agent.agent_nuclei.AgentNuclei.report_vulnerability", return_value=None
    )
    nuclei_agent_no_url_scope.process(scan_message_large_network_range)
    run_command_mock.assert_called()
    run_command_args = run_command_mock.call_args_list
    assert "209.235.0.1" in run_command_args[0].args[0]
    assert "209.235.0.15" in run_command_args[1].args[0]


@mock.patch("agent.agent_nuclei.OUTPUT_PATH", "./tests/result_nuclei.json")
def testAgentNuclei_whenLinkScanned_emitsExactIpWhereVulnWasFound(
    nuclei_agent_no_url_scope: agent_nuclei.AgentNuclei,
    agent_mock: List[message.Message],
    ip_small_range_message: message.Message,
    agent_persist_mock: Dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
) -> None:
    mocker.patch("subprocess.run", return_value=None)
    nuclei_agent_no_url_scope.process(ip_small_range_message)
    assert "v3.report.vulnerability" in [a.selector for a in agent_mock]
    assert ["domain_name"] in [
        list(a.data.get("vulnerability_location", {}).keys()) for a in agent_mock
    ]
    assert agent_mock[0].data["vulnerability_location"] == {
        "domain_name": {"name": "web.com"}
    }


@mock.patch("agent.agent_nuclei.OUTPUT_PATH", "./tests/result_nuclei_non_domain.json")
def testAgentNuclei_whenDomainDoesntExist_emitsDomainAsIs(
    nuclei_agent_no_url_scope: agent_nuclei.AgentNuclei,
    agent_mock: List[message.Message],
    ip_small_range_message: message.Message,
    agent_persist_mock: Dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
) -> None:
    mocker.patch("subprocess.run", return_value=None)
    nuclei_agent_no_url_scope.process(ip_small_range_message)
    assert "v3.report.vulnerability" in [a.selector for a in agent_mock]
    assert ["domain_name"] in [
        list(a.data.get("vulnerability_location", {}).keys()) for a in agent_mock
    ]
    assert agent_mock[0].data["vulnerability_location"] == {
        "domain_name": {"name": "web.comx"}
    }


@mock.patch("agent.agent_nuclei.OUTPUT_PATH", "./tests/result_nuclei_domain.json")
def testAgentNuclei_whenDomainScanned_emitsExactDomainWhereVulnWasFound(
    nuclei_agent_no_url_scope: agent_nuclei.AgentNuclei,
    agent_mock: List[message.Message],
    ip_small_range_message: message.Message,
    agent_persist_mock: Dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
) -> None:
    mocker.patch("subprocess.run", return_value=None)
    nuclei_agent_no_url_scope.process(ip_small_range_message)
    assert "v3.report.vulnerability" in [a.selector for a in agent_mock]
    assert ["domain_name"] in [
        list(a.data.get("vulnerability_location", {}).keys()) for a in agent_mock
    ]
    assert agent_mock[0].data["vulnerability_location"] == {
        "domain_name": {"name": "web.com"}
    }


@mock.patch("agent.agent_nuclei.OUTPUT_PATH", "./tests/result_nuclei_ip.json")
def testAgentNuclei_whenIpScanned_emitsExactIpWhereVulnWasFound(
    nuclei_agent_no_url_scope: agent_nuclei.AgentNuclei,
    agent_mock: List[message.Message],
    ip_small_range_message: message.Message,
    agent_persist_mock: Dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
) -> None:
    mocker.patch("subprocess.run", return_value=None)
    nuclei_agent_no_url_scope.process(ip_small_range_message)
    assert "v3.report.vulnerability" in [a.selector for a in agent_mock]
    assert ["ipv4"] in [
        list(a.data.get("vulnerability_location", {}).keys()) for a in agent_mock
    ]
    assert agent_mock[0].data["vulnerability_location"] == {
        "ipv4": {"host": "45.33.32.83", "mask": "32", "version": 4}
    }


@mock.patch("agent.agent_nuclei.OUTPUT_PATH", "./tests/result_nuclei_ipv6.json")
def testAgentNuclei_whenIpv6Scanned_emitsExactIpWhereVulnWasFound(
    nuclei_agent_no_url_scope: agent_nuclei.AgentNuclei,
    agent_mock: List[message.Message],
    ip_small_range_message: message.Message,
    agent_persist_mock: Dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
) -> None:
    mocker.patch("subprocess.run", return_value=None)
    nuclei_agent_no_url_scope.process(ip_small_range_message)
    assert "v3.report.vulnerability" in [a.selector for a in agent_mock]
    assert ["ipv6"] in [
        list(a.data.get("vulnerability_location", {}).keys()) for a in agent_mock
    ]
    assert agent_mock[0].data["vulnerability_location"] == {
        "ipv6": {
            "host": "FE80:CD00:0000:0CDE:1257:0000:211E:729C",
            "mask": "128",
            "version": 4,
        }
    }


@mock.patch("agent.agent_nuclei.OUTPUT_PATH", "./tests/result_nuclei_ip_port.json")
def testAgentNuclei_whenIpWithPortScanned_emitsExactIpWhereVulnWasFound(
    nuclei_agent_no_url_scope: agent_nuclei.AgentNuclei,
    agent_mock: List[message.Message],
    ip_small_range_message: message.Message,
    agent_persist_mock: Dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
) -> None:
    mocker.patch("subprocess.run", return_value=None)
    nuclei_agent_no_url_scope.process(ip_small_range_message)
    assert "v3.report.vulnerability" in [a.selector for a in agent_mock]
    assert ["ipv4", "metadata"] in [
        list(a.data.get("vulnerability_location", {}).keys()) for a in agent_mock
    ]
    assert agent_mock[0].data["vulnerability_location"] == {
        "ipv4": {"host": "45.33.32.83", "mask": "32", "version": 4},
        "metadata": [{"value": "55", "type": "PORT"}],
    }


@mock.patch("agent.agent_nuclei.OUTPUT_PATH", "./tests/result_nuclei_with_port.json")
def testAgentNuclei_whenLocationHasDomainAndPort_reportedLocationShouldOnlyHaveName(
    nuclei_agent_no_url_scope: agent_nuclei.AgentNuclei,
    agent_mock: List[message.Message],
    ip_small_range_message: message.Message,
    agent_persist_mock: Dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
) -> None:
    mocker.patch("subprocess.run", return_value=None)
    nuclei_agent_no_url_scope.process(ip_small_range_message)

    assert "v3.report.vulnerability" in [a.selector for a in agent_mock]
    assert ["domain_name", "metadata"] in [
        list(a.data.get("vulnerability_location", {}).keys()) for a in agent_mock
    ]
    assert agent_mock[0].data["vulnerability_location"] == {
        "domain_name": {"name": "web.com"},
        "metadata": [{"value": "443", "type": "PORT"}],
    }


@mock.patch("agent.agent_nuclei.OUTPUT_PATH", "./tests/result_nuclei_domain_port.json")
def testAgentNuclei_whenMessageIsDomainWithPort_scanMultipleTargets(
    nuclei_agent_no_url_scope: agent_nuclei.AgentNuclei,
    scan_message_domain: message.Message,
    agent_mock: List[message.Message],
    nuclei_agent: agent_nuclei.AgentNuclei,
    agent_persist_mock: Dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
) -> None:
    mocker.patch("subprocess.run", return_value=None)
    nuclei_agent_no_url_scope.process(scan_message_domain)

    assert "v3.report.vulnerability" in [a.selector for a in agent_mock]
    assert (
        agent_mock[0].data["vulnerability_location"]["domain_name"]["name"]
        == "example.com"
    )


@pytest.mark.parametrize(
    "url, domain_name",
    [
        ("www.example.com", "www.example.com"),
        ("www.example.com:80", "www.example.com"),
        ("https://www.example.com", "www.example.com"),
        ("https://www.example.com:80", "www.example.com"),
        ("example.com:80", "example.com"),
        ("example.com", "example.com"),
    ],
)
def testPrepareDomainAsset_whenUrlGiven_returnsDomainAsset(
    url: str, domain_name: str
) -> None:
    assert helpers.prepare_domain_asset(url) == domain_name


@mock.patch(
    "agent.agent_nuclei.OUTPUT_PATH", "./tests/result_nuclei_matched_at_empty.json"
)
def testAgentNuclei_whenMacthedAtIsInvalid_reportVuln(
    nuclei_agent_no_url_scope: agent_nuclei.AgentNuclei,
    scan_message_domain: message.Message,
    agent_mock: List[message.Message],
    nuclei_agent: agent_nuclei.AgentNuclei,
    agent_persist_mock: Dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
) -> None:
    mocker.patch("subprocess.run", return_value=None)
    nuclei_agent_no_url_scope.process(scan_message_domain)

    assert "v3.report.vulnerability" in [a.selector for a in agent_mock]
    assert agent_mock[0].data.get("vulnerability_location") is None


@mock.patch("agent.agent_nuclei.OUTPUT_PATH", "./tests/result_nuclei.json")
def testAgentNuclei_whenProcessFailed_agentNotCrash(
    requests_mock: rq_mock.mocker.Mocker,
    scan_message: message.Message,
    nuclei_agent_args: agent_nuclei.AgentNuclei,
    agent_persist_mock: Dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
) -> None:
    """Tests running the agent and parsing the json output."""
    run_command_mock = mocker.patch(
        "subprocess.run",
        side_effect=subprocess.CalledProcessError(
            1,
            "/nuclei/nuclei -u 209.235.136.112 -json -irr -silent -o ./tests/result_nuclei.json-json -irr "
            "-silent -o ./tests/result_nuclei.json",
        ),
    )
    mocker.patch("os.path.exists", return_value=True)
    requests_mock.get(
        "https://raw.githubusercontent.com/Ostorlab/main/templates/CVE1.yaml",
        content=b"test1",
    )
    requests_mock.get(
        "https://raw.githubusercontent.com/Ostorlab/main/templates/CVE2.yaml",
        content=b"test2",
    )
    mock_report_vulnerability = mocker.patch(
        "agent.agent_nuclei.AgentNuclei.report_vulnerability", return_value=None
    )
    nuclei_agent_args.process(scan_message)

    run_command_mock.assert_called()
    run_command_args = run_command_mock.call_args_list
    assert "/nuclei/nuclei" in run_command_args[1][0][0]
    assert mock_report_vulnerability.call_count == 0


def testAgentNuclei_whenMessageIsDomainWithUnsupportedSchema_shouldNotScan(
    nuclei_agent_no_url_scope: agent_nuclei.AgentNuclei,
    agent_mock: List[message.Message],
    mocker: plugin.MockerFixture,
) -> None:
    """Tests when the message is a domain with unsupported schema, the agent should not scan it."""

    # Prepare
    subprocess_mock = mocker.patch("subprocess.run", return_value=None)
    input_selector = "v3.asset.link"
    input_data = {"url": "mailto://me@google.com", "method": "GET"}
    link_msg = message.Message.from_data(selector=input_selector, data=input_data)

    # Act
    nuclei_agent_no_url_scope.process(link_msg)

    # Assert
    assert len(agent_mock) == 0
    assert subprocess_mock.call_count == 0


@mock.patch("agent.agent_nuclei.OUTPUT_PATH", "./tests/result_nuclei_critical.json")
def testAgentNuclei_whenNucleiReportsCriticalFinding_emitsCriticalVulnerability(
    scan_message: message.Message,
    nuclei_agent_no_url_scope: agent_nuclei.AgentNuclei,
    agent_persist_mock: Dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
) -> None:
    """Tests running the agent and parsing the json output."""
    mocker.patch("subprocess.run", return_value=None)
    mock_report_vulnerability = mocker.patch(
        "agent.agent_nuclei.AgentNuclei.report_vulnerability", return_value=None
    )
    nuclei_agent_no_url_scope.process(scan_message)
    mock_report_vulnerability.assert_called_once()
    assert (
        mock_report_vulnerability.call_args.kwargs["entry"].cvss_v3_vector
        == "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
    )
    assert (
        """Matched : `ats` at"""
        in mock_report_vulnerability.call_args.kwargs["technical_detail"]
    )
    assert (
        "Author" not in mock_report_vulnerability.call_args.kwargs["technical_detail"]
    )
    assert (
        mock_report_vulnerability.call_args.kwargs["risk_rating"]
        == agent_report_vulnerability_mixin.RiskRating.CRITICAL
    )


@mock.patch(
    "agent.agent_nuclei.OUTPUT_PATH", "./tests/result_nuclei_low_weak_cipher.json"
)
def testAgentNuclei_whenNucleiProcessLink_emitsTechnicalDetailWithLink(
    scan_message_link: message.Message,
    nuclei_agent_no_url_scope: agent_nuclei.AgentNuclei,
    agent_persist_mock: Dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
) -> None:
    """Tests running the agent technical detail for link to have correct scheme."""
    mocker.patch("subprocess.run", return_value=None)
    mock_report_vulnerability = mocker.patch(
        "agent.agent_nuclei.AgentNuclei.report_vulnerability", return_value=None
    )

    nuclei_agent_no_url_scope.process(scan_message_link)

    mock_report_vulnerability.assert_called_once()
    assert (
        """Matched : `tls-1.1` at  `api.mixpanel.com:443`"""
        in mock_report_vulnerability.call_args.kwargs["technical_detail"]
    )
    assert (
        "Author" not in mock_report_vulnerability.call_args.kwargs["technical_detail"]
    )
    assert (
        mock_report_vulnerability.call_args.kwargs["risk_rating"]
        == agent_report_vulnerability_mixin.RiskRating.LOW
    )
