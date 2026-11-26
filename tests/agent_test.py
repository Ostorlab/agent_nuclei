"""Unittests for nuclei class."""

import json
import pathlib
import subprocess
from unittest import mock

import pytest
import requests_mock as rq_mock
from ostorlab.agent.message import message
from ostorlab.agent.mixins import agent_report_vulnerability_mixin
from pytest_mock import plugin

from agent import agent_nuclei, helpers


@mock.patch("agent.agent_nuclei.OUTPUT_PATH", "./tests/result_nuclei.json")
def testAgentNuclei_whenBinaryAvailable_RunScan(
    scan_message: message.Message,
    nuclei_agent_no_url_scope: agent_nuclei.AgentNuclei,
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
    assert (
        mock_report_vulnerability.call_args.kwargs["dna"]
        == '{"location": {"domain_name": {"name": "web.com"}, "metadata": [{"type": "URL", "value": "https://web.com/"}]}, "title": "WAF Detection"}'
    )


@mock.patch("agent.agent_nuclei.OUTPUT_PATH", "./tests/result_nuclei.json")
def testAgentNuclei_whenUrlTemplatesGiven_RunScan(
    requests_mock: rq_mock.mocker.Mocker,
    scan_message: message.Message,
    nuclei_agent_args: agent_nuclei.AgentNuclei,
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
        "209.235.136.112:443",
        "-j",
        "-irr",
        "-silent",
        "-o",
        "./tests/result_nuclei.json",
        "-max-host-error",
        "10",
        "-timeout",
        "7",
        "-retries",
        "1",
    ]
    command = " ".join(run_command_args[0].args[0])
    assert "/nuclei/nuclei" in command
    assert "-u" in command
    assert "209.235.136.112:443" in command
    assert "-j" in command
    assert "-irr" in command
    assert "-silent" in command
    assert "-o" in command
    assert "./tests/result_nuclei.json" in command
    assert "CVE1.yaml" in command
    assert "-t" in command
    assert "CVE2.yaml" in command
    mock_report_vulnerability.assert_called()


@mock.patch("agent.agent_nuclei.OUTPUT_PATH", "./tests/result_nuclei.json")
def testAgentNuclei_whenLinkMessageGiven_NotScan(
    scan_message_link_2: message.Message,
    nuclei_agent: agent_nuclei.AgentNuclei,
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
    command = " ".join(run_command_args[0].args[0])
    assert "/nuclei/nuclei" in command
    assert "-u" in command
    assert "209.235.136.112" in command
    assert "-j" in command
    assert "-irr" in command
    assert "-silent" in command
    assert "-o" in command
    assert "./tests/result_nuclei.json" in command
    assert "-t" in command
    assert "CVE1.yaml" in command
    assert "-t" in command
    assert "CVE2.yaml" in command

    assert run_command_args[1].args == (
        [
            "/nuclei/nuclei",
            "-u",
            "209.235.136.112:443",
            "-j",
            "-irr",
            "-silent",
            "-o",
            "./tests/result_nuclei.json",
            "-max-host-error",
            "10",
            "-timeout",
            "7",
            "-retries",
            "1",
        ],
    )


@mock.patch("agent.agent_nuclei.OUTPUT_PATH", "./tests/result_nuclei.json")
def testAgentNuclei_whenMessageIsIpRange_scanMultipleTargets(
    requests_mock: rq_mock.mocker.Mocker,
    scan_message_network_range: message.Message,
    nuclei_agent_no_url_scope: agent_nuclei.AgentNuclei,
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
    assert "209.235.136.113:443" in run_command_args[0].args[0]
    assert "209.235.136.121:443" in run_command_args[0].args[0]


@mock.patch("agent.agent_nuclei.OUTPUT_PATH", "./tests/result_nuclei.json")
def testAgentNuclei_whenMessageIsDomain_scanMultipleTargets(
    requests_mock: rq_mock.mocker.Mocker,
    scan_message_domain: message.Message,
    nuclei_agent: agent_nuclei.AgentNuclei,
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
    assert "209.235.0.1:443" in run_command_args[0].args[0]
    assert "209.235.0.15:443" in run_command_args[1].args[0]


@mock.patch("agent.agent_nuclei.OUTPUT_PATH", "./tests/result_nuclei.json")
def testAgentNuclei_whenLinkScanned_emitsExactIpWhereVulnWasFound(
    nuclei_agent_no_url_scope: agent_nuclei.AgentNuclei,
    agent_mock: list[message.Message],
    ip_small_range_message: message.Message,
    mocker: plugin.MockerFixture,
) -> None:
    mocker.patch("subprocess.run", return_value=None)

    nuclei_agent_no_url_scope.process(ip_small_range_message)

    assert "v3.report.vulnerability" in [a.selector for a in agent_mock]
    assert (
        agent_mock[0].data["vulnerability_location"]["domain_name"]["name"] == "web.com"
    )
    assert agent_mock[0].data["vulnerability_location"]["metadata"] == [
        {"type": "URL", "value": "https://web.com/"}
    ]


@mock.patch("agent.agent_nuclei.OUTPUT_PATH", "./tests/result_nuclei_non_domain.json")
def testAgentNuclei_whenDomainDoesntExist_emitsDomainAsIs(
    nuclei_agent_no_url_scope: agent_nuclei.AgentNuclei,
    agent_mock: list[message.Message],
    ip_small_range_message: message.Message,
    mocker: plugin.MockerFixture,
) -> None:
    mocker.patch("subprocess.run", return_value=None)

    nuclei_agent_no_url_scope.process(ip_small_range_message)

    assert "v3.report.vulnerability" in [a.selector for a in agent_mock]
    assert (
        agent_mock[0].data["vulnerability_location"]["domain_name"]["name"]
        == "web.comx"
    )
    assert agent_mock[0].data["vulnerability_location"]["metadata"] == [
        {"type": "URL", "value": "https://web.comx/"}
    ]


@mock.patch("agent.agent_nuclei.OUTPUT_PATH", "./tests/result_nuclei_domain.json")
def testAgentNuclei_whenDomainScanned_emitsExactDomainWhereVulnWasFound(
    nuclei_agent_no_url_scope: agent_nuclei.AgentNuclei,
    agent_mock: list[message.Message],
    ip_small_range_message: message.Message,
    mocker: plugin.MockerFixture,
) -> None:
    mocker.patch("subprocess.run", return_value=None)

    nuclei_agent_no_url_scope.process(ip_small_range_message)

    assert "v3.report.vulnerability" in [a.selector for a in agent_mock]
    assert (
        agent_mock[0].data["vulnerability_location"]["domain_name"]["name"] == "web.com"
    )
    assert agent_mock[0].data["vulnerability_location"]["metadata"] == [
        {"type": "URL", "value": "web.com"}
    ]


@mock.patch("agent.agent_nuclei.OUTPUT_PATH", "./tests/result_nuclei_ip.json")
def testAgentNuclei_whenIpScanned_emitsExactIpWhereVulnWasFound(
    nuclei_agent_no_url_scope: agent_nuclei.AgentNuclei,
    agent_mock: list[message.Message],
    ip_small_range_message: message.Message,
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
    agent_mock: list[message.Message],
    ip_small_range_message: message.Message,
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
            "version": 6,
        }
    }


@mock.patch("agent.agent_nuclei.OUTPUT_PATH", "./tests/result_nuclei_ip_port.json")
def testAgentNuclei_whenIpWithPortScanned_emitsExactIpWhereVulnWasFound(
    nuclei_agent_no_url_scope: agent_nuclei.AgentNuclei,
    agent_mock: list[message.Message],
    ip_small_range_message: message.Message,
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
    agent_mock: list[message.Message],
    ip_small_range_message: message.Message,
    mocker: plugin.MockerFixture,
) -> None:
    mocker.patch("subprocess.run", return_value=None)

    nuclei_agent_no_url_scope.process(ip_small_range_message)

    assert "v3.report.vulnerability" in [a.selector for a in agent_mock]
    assert ["domain_name", "metadata"] in [
        list(a.data.get("vulnerability_location", {}).keys()) for a in agent_mock
    ]
    assert (
        agent_mock[0].data["vulnerability_location"]["domain_name"]["name"] == "web.com"
    )
    assert (
        any(
            metadata["type"] == "PORT" and metadata["value"] == "443"
            for metadata in agent_mock[0].data["vulnerability_location"]["metadata"]
        )
        is True
    )
    assert (
        any(
            metadata["type"] == "URL" and metadata["value"] == "https://web.com:443/"
            for metadata in agent_mock[0].data["vulnerability_location"]["metadata"]
        )
        is True
    )


@mock.patch("agent.agent_nuclei.OUTPUT_PATH", "./tests/result_nuclei_domain_port.json")
def testAgentNuclei_whenMessageIsDomainWithPort_scanMultipleTargets(
    nuclei_agent_no_url_scope: agent_nuclei.AgentNuclei,
    scan_message_domain: message.Message,
    agent_mock: list[message.Message],
    nuclei_agent: agent_nuclei.AgentNuclei,
    mocker: plugin.MockerFixture,
) -> None:
    mocker.patch("subprocess.run", return_value=None)

    nuclei_agent_no_url_scope.process(scan_message_domain)

    assert "v3.report.vulnerability" in [a.selector for a in agent_mock]
    assert (
        agent_mock[0].data["vulnerability_location"]["domain_name"]["name"]
        == "example.com"
    )
    assert agent_mock[0].data["vulnerability_location"]["metadata"] == [
        {"type": "URL", "value": "example.com:8080"}
    ]


@mock.patch("agent.agent_nuclei.OUTPUT_PATH", "./tests/result_nuclei_domain_query.json")
def testAgentNuclei_whenMessageIsDomainWithQuery_vulnLocationMetadataDoesNotContainQuery(
    nuclei_agent_no_url_scope: agent_nuclei.AgentNuclei,
    scan_message_domain_query: message.Message,
    agent_mock: list[message.Message],
    mocker: plugin.MockerFixture,
) -> None:
    """Tests running the agent and parsing the json output."""
    mocker.patch("subprocess.run", return_value=None)

    nuclei_agent_no_url_scope.process(scan_message_domain_query)

    assert "v3.report.vulnerability" in [a.selector for a in agent_mock]
    assert (
        agent_mock[0].data["vulnerability_location"]["domain_name"]["name"]
        == "apple.com"
    )
    assert agent_mock[0].data["vulnerability_location"]["metadata"] == [
        {"type": "URL", "value": "apple.com/path/to/something/"}
    ]


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
    agent_mock: list[message.Message],
    nuclei_agent: agent_nuclei.AgentNuclei,
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


@mock.patch("agent.agent_nuclei.OUTPUT_PATH", "./tests/result_nuclei.json")
def testAgentNuclei_whenProcessTimesOut_salvagesExistingOutput(
    scan_message: message.Message,
    nuclei_agent_no_url_scope: agent_nuclei.AgentNuclei,
    mocker: plugin.MockerFixture,
) -> None:
    """Tests running the agent when nuclei times out, ensuring output is salvaged and agent does not crash."""
    run_command_mock = mocker.patch(
        "subprocess.run",
        side_effect=subprocess.TimeoutExpired(
            cmd="/nuclei/nuclei",
            timeout=1800,
        ),
    )
    mock_report_vulnerability = mocker.patch(
        "agent.agent_nuclei.AgentNuclei.report_vulnerability", return_value=None
    )

    nuclei_agent_no_url_scope.process(scan_message)

    run_command_mock.assert_called()
    assert mock_report_vulnerability.call_count == 1


@mock.patch("agent.agent_nuclei.OUTPUT_PATH", "./tests/result_nuclei_empty.json")
def testAgentNuclei_whenProcessTimesOutAndEmptyOutput_agentNotCrash(
    scan_message: message.Message,
    nuclei_agent_no_url_scope: agent_nuclei.AgentNuclei,
    mocker: plugin.MockerFixture,
) -> None:
    """Tests running the agent when nuclei times out with empty output, ensuring agent does not crash."""
    run_command_mock = mocker.patch(
        "subprocess.run",
        side_effect=subprocess.TimeoutExpired(
            cmd="/nuclei/nuclei",
            timeout=1800,
        ),
    )
    mock_report_vulnerability = mocker.patch(
        "agent.agent_nuclei.AgentNuclei.report_vulnerability", return_value=None
    )

    nuclei_agent_no_url_scope.process(scan_message)

    run_command_mock.assert_called()
    assert mock_report_vulnerability.call_count == 0


@mock.patch("agent.agent_nuclei.OUTPUT_PATH", "./tests/result_nuclei_empty.json")
def testAgentNuclei_whenRunCommand_timeoutPassedToSubprocess(
    scan_message: message.Message,
    nuclei_agent_no_url_scope: agent_nuclei.AgentNuclei,
    mocker: plugin.MockerFixture,
) -> None:
    """Tests that subprocess.run is called with the expected timeout of 30 minutes (1800s)."""
    run_command_mock = mocker.patch("subprocess.run", return_value=None)

    nuclei_agent_no_url_scope.process(scan_message)

    run_command_mock.assert_called()
    for call in run_command_mock.call_args_list:
        assert call.kwargs.get("timeout") == 1800


def testAgentNuclei_whenMessageIsDomainWithUnsupportedSchema_shouldNotScan(
    nuclei_agent_no_url_scope: agent_nuclei.AgentNuclei,
    agent_mock: list[message.Message],
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
        """Matched : `tls-1.1` at `api.mixpanel.com:443`"""
        in mock_report_vulnerability.call_args.kwargs["technical_detail"]
    )
    assert (
        "Author" not in mock_report_vulnerability.call_args.kwargs["technical_detail"]
    )
    assert (
        mock_report_vulnerability.call_args.kwargs["risk_rating"]
        == agent_report_vulnerability_mixin.RiskRating.LOW
    )


@pytest.mark.parametrize(
    "test_message",
    [
        message.Message.from_data(
            "v3.asset.ip.v4",
            data={"host": "209.235.136.112", "mask": "32", "version": 4},
        ),
        message.Message.from_data(
            "v3.asset.ip.v4",
            data={"host": "209.235.136.112", "mask": "16", "version": 4},
        ),
        message.Message.from_data(
            "v3.asset.link", data={"url": "https://apple.com", "method": "GET"}
        ),
        message.Message.from_data("v3.asset.domain_name", data={"name": "apple.com"}),
    ],
)
@mock.patch("agent.agent_nuclei.OUTPUT_PATH", "../tests/result_nuclei.json")
def testAgentNuclei_whenSameMessageSentTwice_shouldScanOnlyOnce(
    test_message: message.Message,
    nuclei_agent_args: agent_nuclei.AgentNuclei,
    mocker: plugin.MockerFixture,
) -> None:
    """Test nuclei agent should not scan the same message twice."""
    prepare_target_mock = mocker.patch("agent.agent_nuclei.AgentNuclei.prepare_targets")

    nuclei_agent_args.process(test_message)
    nuclei_agent_args.process(test_message)

    prepare_target_mock.assert_called_once()


@mock.patch("agent.agent_nuclei.OUTPUT_PATH", "../tests/result_nuclei.json")
def testAgentNuclei_whenUnknownTarget_shouldntBeProcessed(
    nuclei_agent_args: agent_nuclei.AgentNuclei,
    mocker: plugin.MockerFixture,
) -> None:
    """Test nuclei agent should not scan message with unknown target."""
    prepare_target_mock = mocker.patch("agent.agent_nuclei.AgentNuclei.prepare_targets")
    msg = message.Message.from_data(
        "v3.asset.file", data={"path": "libagora-crypto.so"}
    )

    nuclei_agent_args.process(msg)

    prepare_target_mock.assert_not_called()


@mock.patch("agent.agent_nuclei.OUTPUT_PATH", "./tests/result_nuclei_empty.json")
def testAgentNuclei_whenBasicCredentialProvided_shouldRunCommandWithBasicAuthHeader(
    scan_message_link_with_basic_credential: message.Message,
    nuclei_agent_no_url_scope: agent_nuclei.AgentNuclei,
    mocker: plugin.MockerFixture,
) -> None:
    """Ensure that AgentNuclei runs the nuclei command with the basic Auth header when basic credentials are given."""
    run_command_mock = mocker.patch("subprocess.run", return_value=None)

    nuclei_agent_no_url_scope.process(scan_message_link_with_basic_credential)

    run_command_mock.assert_called()
    run_command_args = run_command_mock.call_args_list
    assert "-H" in run_command_args[0].args[0]
    assert (
        "Authorization: Basic dXNlcm5hbWU6ZHVtbXlfdmFsdWU="
        in run_command_args[0].args[0]
    )


@mock.patch("agent.agent_nuclei.OUTPUT_PATH", "./tests/result_nuclei_empty.json")
def testAgentNuclei_whenBasicCredentialNotProvided_shouldRunCommandWithoutBasicAuthHeader(
    scan_message_link_2: message.Message,
    nuclei_agent_no_url_scope: agent_nuclei.AgentNuclei,
    mocker: plugin.MockerFixture,
) -> None:
    """Ensure that AgentNuclei runs the nuclei command without a basic Auth header when basic credentials are not
    given."""
    run_command_mock = mocker.patch("subprocess.run", return_value=None)

    nuclei_agent_no_url_scope.process(scan_message_link_2)

    run_command_mock.assert_called()
    run_command_args = run_command_mock.call_args_list
    assert "-H" not in run_command_args[0].args[0]


@mock.patch("agent.agent_nuclei.OUTPUT_PATH", "./tests/result_nuclei_empty.json")
def testAgentNuclei_whenBasicCredentialProvidedFromArgs_shouldRunCommandWithBasicAuthHeader(
    scan_message_link_2: message.Message,
    nuclei_agent_with_basic_credentials: agent_nuclei.AgentNuclei,
    mocker: plugin.MockerFixture,
) -> None:
    """Ensure that AgentNuclei runs the nuclei command with the basic Auth header when basic credentials are given
    from args."""
    run_command_mock = mocker.patch("subprocess.run", return_value=None)

    nuclei_agent_with_basic_credentials.process(scan_message_link_2)

    run_command_mock.assert_called()
    run_command_args = run_command_mock.call_args_list
    assert "-H" in run_command_args[0].args[0]
    assert "-H" in run_command_args[0].args[0]
    assert (
        "Authorization: Basic dXNlcm5hbWU6ZHVtbXlfdmFsdWU="
        in run_command_args[0].args[0]
    )


@mock.patch("agent.agent_nuclei.OUTPUT_PATH", "./tests/result_nuclei.json")
def testAgentNuclei_withTemplateIds_RunScan(
    scan_message: message.Message,
    nuclei_agent_with_template_ids: agent_nuclei.AgentNuclei,
    mocker: plugin.MockerFixture,
) -> None:
    """Tests running the agent when template_ids are provided."""
    run_command_mock = mocker.patch("subprocess.run", return_value=None)
    mocker.patch(
        "agent.agent_nuclei.AgentNuclei.report_vulnerability", return_value=None
    )

    nuclei_agent_with_template_ids.process(scan_message)

    run_command_args = run_command_mock.call_args_list
    command = " ".join(run_command_args[0].args[0])
    assert "/nuclei/nuclei" in command
    assert "-id" in command
    assert "cve-2021-1234" in command
    assert "cve-2021-5678" in command
    assert "-t" not in run_command_args[0].args[0]
    command_default = " ".join(run_command_args[1].args[0])
    assert "-id" not in command_default


@mock.patch("agent.agent_nuclei.OUTPUT_PATH", "./tests/result_nuclei.json")
def testAgentNuclei_withCustomTemplates_RunScan(
    scan_message: message.Message,
    nuclei_agent_with_custom_templates: agent_nuclei.AgentNuclei,
    mocker: plugin.MockerFixture,
    requests_mock: rq_mock.mocker.Mocker,
) -> None:
    """Tests running the agent when templates are provided."""
    run_command_mock = mocker.patch("subprocess.run", return_value=None)
    mocker.patch(
        "agent.agent_nuclei.AgentNuclei.report_vulnerability", return_value=None
    )
    requests_mock.get("https://template1.yaml", json={})
    requests_mock.get("https://template2.yaml", json={})

    nuclei_agent_with_custom_templates.process(scan_message)

    run_command_args = run_command_mock.call_args_list
    command = " ".join(run_command_args[0].args[0])
    assert "/nuclei/nuclei" in command
    assert "-u" in command
    assert "209.235.136.112:443" in command
    assert "-j" in command
    assert "-irr" in command
    assert "-silent" in command
    assert "-o" in command
    assert "./tests/result_nuclei.json" in command
    assert "-t" in command
    assert "template1.yaml" in command
    assert "-t" in command
    assert "template2.yaml" in command


def testPrepareTargets_whenIPv4AssetReachCIDRLimit_raiseValueError(
    scan_message_ipv4_with_mask8: message.Message,
    nuclei_agent: agent_nuclei.AgentNuclei,
) -> None:
    with pytest.raises(ValueError, match="Subnet mask below 16 is not supported."):
        nuclei_agent.prepare_targets(scan_message_ipv4_with_mask8)


def testPrepareTargets_whenIPv4AssetDoesNotReachCIDRLimit_doesNotRaiseValueError(
    scan_message_network_range: message.Message,
    nuclei_agent: agent_nuclei.AgentNuclei,
) -> None:
    nuclei_agent.prepare_targets(scan_message_network_range)


def testPrepareTargets_whenIPv6AssetReachCIDRLimit_raiseValueError(
    scan_message_ipv6_with_mask64: message.Message,
    nuclei_agent: agent_nuclei.AgentNuclei,
) -> None:
    with pytest.raises(ValueError, match="Subnet mask below 112 is not supported."):
        nuclei_agent.prepare_targets(scan_message_ipv6_with_mask64)


def testPrepareTargets_whenIPv6AssetDoesNotReachCIDRLimit_doesNotRaiseValueError(
    scan_message_ipv6_with_mask112: message.Message,
    nuclei_agent: agent_nuclei.AgentNuclei,
) -> None:
    nuclei_agent.prepare_targets(scan_message_ipv6_with_mask112)


@mock.patch("agent.agent_nuclei.OUTPUT_PATH", "./tests/result_nuclei.json")
def testAgentNuclei_whenProxyIsProvided_shouldCallWithProxyArg(
    scan_message: message.Message,
    nuclei_agent_with_proxy: agent_nuclei.AgentNuclei,
    mocker: plugin.MockerFixture,
    requests_mock: rq_mock.mocker.Mocker,
) -> None:
    """Tests running the agent when proxy is provided."""
    run_command_mock = mocker.patch("subprocess.run", return_value=None)
    mocker.patch(
        "agent.agent_nuclei.AgentNuclei.report_vulnerability", return_value=None
    )
    requests_mock.get("https://template1.yaml", json={})
    requests_mock.get("https://template2.yaml", json={})

    nuclei_agent_with_proxy.process(scan_message)

    run_command_args = run_command_mock.call_args_list
    command = " ".join(run_command_args[0].args[0])
    assert "/nuclei/nuclei" in command
    assert "-proxy" in command
    assert "https://proxy.co" in command


@mock.patch("agent.agent_nuclei.OUTPUT_PATH", "./tests/result_nuclei_long.json")
def testAgentNuclei_whenDescriptionIsLong_shouldNotTruncate(
    scan_message_link_with_basic_credential: message.Message,
    nuclei_agent_no_url_scope: agent_nuclei.AgentNuclei,
    mocker: plugin.MockerFixture,
    agent_mock: list[message.Message],
) -> None:
    """Ensure that AgentNuclei runs the nuclei command with the basic Auth header when basic credentials are given."""
    mocker.patch("subprocess.run", return_value=None)

    nuclei_agent_no_url_scope.process(scan_message_link_with_basic_credential)

    assert "v3.report.vulnerability" in [a.selector for a in agent_mock]
    assert (
        agent_mock[0].data["description"]
        == "The SSH transport protocol with certain OpenSSH extensions, found in OpenSSH before 9.6 and other products, allows remote attackers to bypass integrity checks such that some packets are omitted (from the extension negotiation message), and a client and server may consequently end up with a connection for which some security features have been downgraded or disabled, aka a Terrapin attack. This occurs because the SSH Binary Packet Protocol (BPP), implemented by these extensions, mishandles the handshake phase and mishandles use of sequence numbers. For example, there is an effective attack against SSH's use of ChaCha20-Poly1305 (and CBC with Encrypt-then-MAC). The bypass occurs in chacha20-poly1305@openssh.com and (if CBC is used) the -etm@openssh.com MAC algorithms. This also affects Maverick Synergy Java SSH API before 3.1.0-SNAPSHOT, Dropbear through 2022.83, Ssh before 5.1.1 in Erlang/OTP, PuTTY before 0.80, AsyncSSH before 2.14.2, golang.org/x/crypto before 0.17.0, libssh before 0.10.6, libssh2 through 1.11.0, Thorn Tech SFTP Gateway before 3.4.6, Tera Term before 5.1, Paramiko before 3.4.0, jsch before 0.2.15, SFTPGo before 2.5.6, Netgate pfSense Plus through 23.09.1, Netgate pfSense CE through 2.7.2, HPN-SSH through 18.2.0, ProFTPD before 1.3.8b (and before 1.3.9rc2), ORYX CycloneSSH before 2.3.4, NetSarang XShell 7 before Build 0144, CrushFTP before 10.6.0, ConnectBot SSH library before 2.2.22, Apache MINA sshd through 2.11.0, sshj through 0.37.0, TinySSH through 20230101, trilead-ssh2 6401, LANCOM LCOS and LANconfig, FileZilla before 3.66.4, Nova before 11.8, PKIX-SSH before 14.4, SecureCRT before 9.4.3, Transmit5 before 5.10.4, Win32-OpenSSH before 9.5.0.0p1-Beta, WinSCP before 6.2.2, Bitvise SSH Server before 9.32, Bitvise SSH Client before 9.33, KiTTY through 0.76.1.13, the net-ssh gem 7.2.0 for Ruby, the mscdex ssh2 module before 1.15.0 for Node.js, the thrussh library before 0.35.1 for Rust, and the Russh crate before 0.40.2 for Rust.\n"
    )


@mock.patch("agent.agent_nuclei.OUTPUT_PATH", "./tests/invalid_nuclei_result.json")
def testAgentNuclei_whenResultIsInvalidJson_agentShouldHandleExceptionAndDoNotRaise(
    scan_message: message.Message,
    nuclei_agent_no_url_scope: agent_nuclei.AgentNuclei,
    mocker: plugin.MockerFixture,
    agent_mock: list[message.Message],
) -> None:
    """Ensure the agent handles `json.decoder.JSONDecodeError` exceptions."""
    mocker.patch("subprocess.run", return_value=None)

    nuclei_agent_no_url_scope.process(scan_message)

    assert len(agent_mock) == 0


@mock.patch(
    "agent.agent_nuclei.OUTPUT_PATH", "./tests/result_nuclei_form_detection_fp.json"
)
def testAgentNuclei_whenFormDetectionMatchesGenericPage_shouldNotReport(
    scan_message: message.Message,
    nuclei_agent_no_url_scope: agent_nuclei.AgentNuclei,
    mocker: plugin.MockerFixture,
) -> None:
    """The upstream `form-detection` template reports any page whose body contains an HTML form,
    including third-party pages reached through redirects, so the finding is a known false
    positive and must not be reported."""
    mocker.patch("subprocess.run", return_value=None)
    mock_report_vulnerability = mocker.patch(
        "agent.agent_nuclei.AgentNuclei.report_vulnerability", return_value=None
    )

    nuclei_agent_no_url_scope.process(scan_message)

    mock_report_vulnerability.assert_not_called()


@mock.patch(
    "agent.agent_nuclei.OUTPUT_PATH",
    "./tests/result_nuclei_dns_waf_cloudflare_fp.json",
)
def testAgentNuclei_whenDnsWafDetectMatchesCloudflareNameservers_shouldNotReport(
    scan_message: message.Message,
    nuclei_agent_no_url_scope: agent_nuclei.AgentNuclei,
    mocker: plugin.MockerFixture,
) -> None:
    """The upstream `dns-waf-detect` template's `cloudflare` matcher reports a DNS WAF whenever
    the DNS answer carries a Cloudflare nameserver (`ns.cloudflare.com`), which only indicates
    ordinary authoritative DNS hosting, so the finding is a false positive and must not be
    reported."""
    mocker.patch("subprocess.run", return_value=None)
    mock_report_vulnerability = mocker.patch(
        "agent.agent_nuclei.AgentNuclei.report_vulnerability", return_value=None
    )

    nuclei_agent_no_url_scope.process(scan_message)

    mock_report_vulnerability.assert_not_called()


@mock.patch(
    "agent.agent_nuclei.OUTPUT_PATH", "./tests/result_nuclei_cookie_deletion_fp.json"
)
def testAgentNuclei_whenCookieAttributeMatchesDeletionDirective_shouldNotReport(
    scan_message: message.Message,
    nuclei_agent_no_url_scope: agent_nuclei.AgentNuclei,
    mocker: plugin.MockerFixture,
) -> None:
    """The upstream `missing-cookie-samesite-strict` template treats an expired cookie-deletion
    directive (`session=deleted; Max-Age=0; expires=1970`) as an application session cookie, so
    the finding is a false positive and must not be reported."""
    mocker.patch("subprocess.run", return_value=None)
    mock_report_vulnerability = mocker.patch(
        "agent.agent_nuclei.AgentNuclei.report_vulnerability", return_value=None
    )

    nuclei_agent_no_url_scope.process(scan_message)

    mock_report_vulnerability.assert_not_called()


@mock.patch(
    "agent.agent_nuclei.OUTPUT_PATH",
    "./tests/result_nuclei_cookie_infrastructure_fp.json",
)
def testAgentNuclei_whenCookieAttributeMatchesInfrastructureCookie_shouldNotReport(
    scan_message: message.Message,
    nuclei_agent_no_url_scope: agent_nuclei.AgentNuclei,
    mocker: plugin.MockerFixture,
) -> None:
    """The upstream `cookies-without-secure` template flags Cloudflare's `__cf_bm` bot-management
    cookie as an application cookie gap, so the finding is a false positive and must not be
    reported."""
    mocker.patch("subprocess.run", return_value=None)
    mock_report_vulnerability = mocker.patch(
        "agent.agent_nuclei.AgentNuclei.report_vulnerability", return_value=None
    )

    nuclei_agent_no_url_scope.process(scan_message)

    mock_report_vulnerability.assert_not_called()


@mock.patch(
    "agent.agent_nuclei.OUTPUT_PATH", "./tests/result_nuclei_cookie_app_session.json"
)
def testAgentNuclei_whenCookieAttributeMatchesAppSessionCookie_shouldReport(
    scan_message: message.Message,
    nuclei_agent_no_url_scope: agent_nuclei.AgentNuclei,
    mocker: plugin.MockerFixture,
) -> None:
    """A genuine application session cookie missing the SameSite attribute must still be reported:
    the cookie-attribute suppression only covers infrastructure and deletion cookies."""
    mocker.patch("subprocess.run", return_value=None)
    mock_report_vulnerability = mocker.patch(
        "agent.agent_nuclei.AgentNuclei.report_vulnerability", return_value=None
    )

    nuclei_agent_no_url_scope.process(scan_message)

    mock_report_vulnerability.assert_called_once()


@pytest.mark.parametrize(
    "cookie",
    [
        "session=active; Max-Age=01",
        "session=active; Max-Age=0.5",
        "session=max-age=0dark; Path=/",
        "session=; Path=/",
        "session=deleted; Path=/",
        "session=expires=1970; Path=/",
        "session=active; Expires=invalid-1970",
        "session=active; Max-Age=3600; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
        "session=active; Max-Age=3600; Max-Age=invalid; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
    ],
)
def testAgentNuclei_whenCookieHasNoDeletionExpiry_shouldReport(
    cookie: str,
    tmp_path: pathlib.Path,
    scan_message: message.Message,
    nuclei_agent_no_url_scope: agent_nuclei.AgentNuclei,
    mocker: plugin.MockerFixture,
) -> None:
    """Cookie contents do not delete cookies, and Max-Age overrides Expires."""
    event = json.loads(
        pathlib.Path("tests/result_nuclei_cookie_app_session.json").read_text()
    )
    event["response"] = f"HTTP/1.1 200 OK\r\nSet-Cookie: {cookie}\r\n\r\n"
    output_path = tmp_path / "nuclei.json"
    output_path.write_text(json.dumps(event))
    mocker.patch("agent.agent_nuclei.OUTPUT_PATH", str(output_path))
    mocker.patch("subprocess.run", return_value=None)
    report = mocker.patch("agent.agent_nuclei.AgentNuclei.report_vulnerability")

    nuclei_agent_no_url_scope.process(scan_message)

    report.assert_called_once()
    assert "Missing Cookie SameSite Strict" in report.call_args.kwargs["entry"].title


def testAgentNuclei_whenBodyContainsDeletionHeader_shouldReport(
    tmp_path: pathlib.Path,
    scan_message: message.Message,
    nuclei_agent_no_url_scope: agent_nuclei.AgentNuclei,
    mocker: plugin.MockerFixture,
) -> None:
    """Text in an HTML response body cannot prove a cookie finding is spurious."""
    event = json.loads(
        pathlib.Path("tests/result_nuclei_cookie_app_session.json").read_text()
    )
    event["response"] = (
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nSet-Cookie: session=deleted; Max-Age=0"
    )
    output_path = tmp_path / "nuclei.json"
    output_path.write_text(json.dumps(event))
    mocker.patch("agent.agent_nuclei.OUTPUT_PATH", str(output_path))
    mocker.patch("subprocess.run", return_value=None)
    report = mocker.patch("agent.agent_nuclei.AgentNuclei.report_vulnerability")

    nuclei_agent_no_url_scope.process(scan_message)

    report.assert_called_once()
    assert "Missing Cookie SameSite Strict" in report.call_args.kwargs["entry"].title


def testPrepareTargets_whenMessageIsDomainName_shouldReturnDomainName(
    scan_message_ipv4_with_port: message.Message,
    nuclei_agent: agent_nuclei.AgentNuclei,
) -> None:
    assert nuclei_agent.prepare_targets(scan_message_ipv4_with_port) == [
        "192.168.0.1:8080"
    ]


@pytest.mark.parametrize("is_mask_set", [True, False])
def testNucleiAgent_whenAnIpReceivedWithDifferentPort_shouldScanBothPorts(
    scan_message_ipv4_with_port: message.Message,
    nuclei_agent: agent_nuclei.AgentNuclei,
    mocker: plugin.MockerFixture,
    is_mask_set: bool,
) -> None:
    prepare_targets_mock = mocker.patch(
        "agent.agent_nuclei.AgentNuclei.prepare_targets", return_value=[]
    )
    if is_mask_set is False:
        scan_message_ipv4_with_port.data.pop("mask")
    nuclei_agent.process(scan_message_ipv4_with_port)
    scan_message_ipv4_with_port.data["port"] = 8081

    nuclei_agent.process(scan_message_ipv4_with_port)

    assert prepare_targets_mock.call_count == 2


@pytest.mark.parametrize("is_mask_set", [True, False])
def testNucleiAgent_whenAnIpReceivedWithSamePort_shouldScanOnce(
    scan_message_ipv4_with_port: message.Message,
    nuclei_agent: agent_nuclei.AgentNuclei,
    mocker: plugin.MockerFixture,
    is_mask_set: bool,
) -> None:
    if is_mask_set is False:
        scan_message_ipv4_with_port.data.pop("mask")
    prepare_targets_mock = mocker.patch(
        "agent.agent_nuclei.AgentNuclei.prepare_targets", return_value=[]
    )
    nuclei_agent.process(scan_message_ipv4_with_port)
    scan_message_ipv4_with_port.data["port"] = 8080

    nuclei_agent.process(scan_message_ipv4_with_port)

    assert prepare_targets_mock.call_count == 1


def testPrepareTargets_whenMessageIsApiSchema_shouldReturnEndpointUrl(
    scan_message_api_schema: message.Message,
    nuclei_agent_no_url_scope: agent_nuclei.AgentNuclei,
) -> None:
    """Test that api_schema messages with endpoint_url are correctly prepared as targets."""
    targets = nuclei_agent_no_url_scope.prepare_targets(scan_message_api_schema)

    assert targets == ["https://api.example.com/v1/users"]


def testPrepareTargets_whenMessageIsApiSchemaWithPort_shouldReturnEndpointUrlWithPort(
    scan_message_api_schema_with_port: message.Message,
    nuclei_agent_no_url_scope: agent_nuclei.AgentNuclei,
) -> None:
    """Test that api_schema messages with endpoint_url containing port are correctly prepared."""
    targets = nuclei_agent_no_url_scope.prepare_targets(
        scan_message_api_schema_with_port
    )

    assert targets == ["https://api.example.com:8443/v1/users"]


def testPrepareTargets_whenMessageIsApiSchemaHttp_shouldReturnHttpEndpointUrl(
    scan_message_api_schema_http: message.Message,
    nuclei_agent_no_url_scope: agent_nuclei.AgentNuclei,
) -> None:
    """Test that api_schema messages with http protocol are correctly prepared."""
    targets = nuclei_agent_no_url_scope.prepare_targets(scan_message_api_schema_http)

    assert targets == ["http://api.example.com/v1/data"]


@mock.patch("agent.agent_nuclei.OUTPUT_PATH", "./tests/result_nuclei.json")
def testAgentNuclei_whenApiSchemaMessageReceived_shouldRunScan(
    scan_message_api_schema: message.Message,
    nuclei_agent_no_url_scope: agent_nuclei.AgentNuclei,
    mocker: plugin.MockerFixture,
) -> None:
    """Test that the agent processes api_schema messages and runs nuclei scan."""
    mocker.patch("subprocess.run", return_value=None)
    mock_report_vulnerability = mocker.patch(
        "agent.agent_nuclei.AgentNuclei.report_vulnerability", return_value=None
    )

    nuclei_agent_no_url_scope.process(scan_message_api_schema)

    mock_report_vulnerability.assert_called_once()
    assert (
        mock_report_vulnerability.call_args.kwargs["entry"].cvss_v3_vector
        == "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
    )


def testNucleiAgent_whenSameApiSchemaReceivedTwice_shouldScanOnce(
    scan_message_api_schema: message.Message,
    nuclei_agent_no_url_scope: agent_nuclei.AgentNuclei,
    mocker: plugin.MockerFixture,
) -> None:
    """Test that duplicate api_schema messages are only processed once."""
    prepare_targets_mock = mocker.patch(
        "agent.agent_nuclei.AgentNuclei.prepare_targets", return_value=[]
    )

    nuclei_agent_no_url_scope.process(scan_message_api_schema)
    nuclei_agent_no_url_scope.process(scan_message_api_schema)

    assert prepare_targets_mock.call_count == 1


def testNucleiAgent_whenDifferentApiSchemaEndpoints_shouldScanBoth(
    scan_message_api_schema: message.Message,
    scan_message_api_schema_http: message.Message,
    nuclei_agent_no_url_scope: agent_nuclei.AgentNuclei,
    mocker: plugin.MockerFixture,
) -> None:
    """Test that different api_schema endpoints are both scanned."""
    prepare_targets_mock = mocker.patch(
        "agent.agent_nuclei.AgentNuclei.prepare_targets", return_value=[]
    )

    nuclei_agent_no_url_scope.process(scan_message_api_schema)
    nuclei_agent_no_url_scope.process(scan_message_api_schema_http)

    assert prepare_targets_mock.call_count == 2


@mock.patch("agent.agent_nuclei.OUTPUT_PATH", "./tests/result_nuclei.json")
def testAgentNuclei_whenScanning_passesErrorTimeoutAndRetryFlagsToNuclei(
    scan_message_domain: message.Message,
    nuclei_agent: agent_nuclei.AgentNuclei,
    mocker: plugin.MockerFixture,
) -> None:
    run_command_mock = mocker.patch("subprocess.run", return_value=None)

    nuclei_agent.process(scan_message_domain)

    command = run_command_mock.call_args_list[0].args[0]
    assert command[command.index("-max-host-error") + 1] == "10"
    assert command[command.index("-timeout") + 1] == "7"
    assert command[command.index("-retries") + 1] == "1"


@mock.patch("agent.agent_nuclei.OUTPUT_PATH", "./tests/result_nuclei.json")
def testAgentNuclei_whenTargetIsUnreachable_skipsTheScan(
    scan_message_domain: message.Message,
    nuclei_agent: agent_nuclei.AgentNuclei,
    mocker: plugin.MockerFixture,
) -> None:
    mocker.patch("agent.helpers.is_target_reachable", return_value=False)
    run_command_mock = mocker.patch("subprocess.run", return_value=None)

    nuclei_agent.process(scan_message_domain)

    run_command_mock.assert_not_called()


@mock.patch("agent.agent_nuclei.OUTPUT_PATH", "./tests/result_nuclei.json")
def testAgentNuclei_whenSkippingUnreachableTargetsIsDisabled_scansTheTarget(
    scan_message_domain: message.Message,
    nuclei_agent: agent_nuclei.AgentNuclei,
    mocker: plugin.MockerFixture,
) -> None:
    mocker.patch("agent.helpers.is_target_reachable", return_value=False)
    run_command_mock = mocker.patch("subprocess.run", return_value=None)
    nuclei_agent._skip_unreachable_targets = False

    nuclei_agent.process(scan_message_domain)

    run_command_mock.assert_called()


@mock.patch("agent.agent_nuclei.OUTPUT_PATH", "./tests/result_nuclei.json")
def testAgentNuclei_whenProxyIsSet_doesNotProbeTheTargets(
    scan_message_domain: message.Message,
    nuclei_agent: agent_nuclei.AgentNuclei,
    mocker: plugin.MockerFixture,
) -> None:
    probe_mock = mocker.patch("agent.helpers.is_target_reachable", return_value=False)
    run_command_mock = mocker.patch("subprocess.run", return_value=None)
    nuclei_agent._proxy = "http://proxy.local:3128"

    nuclei_agent.process(scan_message_domain)

    probe_mock.assert_not_called()
    run_command_mock.assert_called()


TEMPLATE_1_URL = "https://raw.githubusercontent.com/Ostorlab/main/templates/CVE1.yaml"
TEMPLATE_2_URL = "https://raw.githubusercontent.com/Ostorlab/main/templates/CVE2.yaml"


@mock.patch("agent.agent_nuclei.OUTPUT_PATH", "./tests/result_nuclei.json")
def testAgentNuclei_whenSeveralTargetsScanned_downloadsTemplatesOnce(
    requests_mock: rq_mock.mocker.Mocker,
    nuclei_agent_args: agent_nuclei.AgentNuclei,
    mocker: plugin.MockerFixture,
) -> None:
    run_command_mock = mocker.patch("subprocess.run", return_value=None)
    mocker.patch("os.path.exists", return_value=True)
    template_1 = requests_mock.get(TEMPLATE_1_URL, content=b"test1")
    template_2 = requests_mock.get(TEMPLATE_2_URL, content=b"test2")
    first_target = message.Message.from_data(
        "v3.asset.domain_name", data={"name": "first.example.com"}
    )
    second_target = message.Message.from_data(
        "v3.asset.domain_name", data={"name": "second.example.com"}
    )

    nuclei_agent_args.process(first_target)
    nuclei_agent_args.process(second_target)

    assert template_1.call_count == 1
    assert template_2.call_count == 1
    commands = [" ".join(c.args[0]) for c in run_command_mock.call_args_list]
    assert any("first.example.com" in c and "CVE2.yaml" in c for c in commands)
    assert any("second.example.com" in c and "CVE2.yaml" in c for c in commands)


@mock.patch("agent.agent_nuclei.OUTPUT_PATH", "./tests/result_nuclei.json")
def testAgentNuclei_whenTemplateDownloadFailsOnce_retriesItBeforeScanningTheSameTarget(
    requests_mock: rq_mock.mocker.Mocker,
    scan_message_domain: message.Message,
    nuclei_agent_args: agent_nuclei.AgentNuclei,
    mocker: plugin.MockerFixture,
) -> None:
    sleep_mock = mocker.patch("agent.agent_nuclei.time.sleep")
    run_command_mock = mocker.patch("subprocess.run", return_value=None)
    mocker.patch("os.path.exists", return_value=True)
    requests_mock.get(TEMPLATE_1_URL, content=b"test1")
    template_2 = requests_mock.get(
        TEMPLATE_2_URL,
        [{"status_code": 503}, {"status_code": 200, "content": b"test2"}],
    )

    nuclei_agent_args.process(scan_message_domain)

    assert template_2.call_count == 2
    sleep_mock.assert_called_once_with(agent_nuclei.TEMPLATE_DOWNLOAD_BACKOFF_SECONDS)
    custom_template_commands = [
        " ".join(c.args[0])
        for c in run_command_mock.call_args_list
        if "-t" in c.args[0]
    ]
    assert len(custom_template_commands) == 1
    assert "CVE1.yaml" in custom_template_commands[0]
    assert "CVE2.yaml" in custom_template_commands[0]


@mock.patch("agent.agent_nuclei.OUTPUT_PATH", "./tests/result_nuclei.json")
def testAgentNuclei_whenTemplateDownloadKeepsFailing_givesUpAfterBoundedRetriesAndTriesAgainOnNextTarget(
    requests_mock: rq_mock.mocker.Mocker,
    nuclei_agent_args: agent_nuclei.AgentNuclei,
    mocker: plugin.MockerFixture,
) -> None:
    mocker.patch("agent.agent_nuclei.time.sleep")
    run_command_mock = mocker.patch("subprocess.run", return_value=None)
    mocker.patch("os.path.exists", return_value=True)
    requests_mock.get(TEMPLATE_1_URL, content=b"test1")
    template_2 = requests_mock.get(TEMPLATE_2_URL, status_code=503)
    first_target = message.Message.from_data(
        "v3.asset.domain_name", data={"name": "first.example.com"}
    )
    second_target = message.Message.from_data(
        "v3.asset.domain_name", data={"name": "second.example.com"}
    )

    nuclei_agent_args.process(first_target)

    attempts_per_target = agent_nuclei.TEMPLATE_DOWNLOAD_RETRIES + 1
    assert template_2.call_count == attempts_per_target
    custom_template_commands = [
        " ".join(c.args[0])
        for c in run_command_mock.call_args_list
        if "-t" in c.args[0]
    ]
    assert len(custom_template_commands) == 1
    assert "CVE1.yaml" in custom_template_commands[0]
    assert "CVE2.yaml" not in custom_template_commands[0]

    nuclei_agent_args.process(second_target)

    assert template_2.call_count == 2 * attempts_per_target


@mock.patch("agent.agent_nuclei.OUTPUT_PATH", "./tests/result_nuclei.json")
def testAgentNuclei_whenAllTemplateDownloadsFail_doesNotRunCustomTemplates(
    requests_mock: rq_mock.mocker.Mocker,
    scan_message_domain: message.Message,
    nuclei_agent_args: agent_nuclei.AgentNuclei,
    mocker: plugin.MockerFixture,
) -> None:
    mocker.patch("agent.agent_nuclei.time.sleep")
    run_command_mock = mocker.patch("subprocess.run", return_value=None)
    requests_mock.get(TEMPLATE_1_URL, status_code=404)
    requests_mock.get(TEMPLATE_2_URL, status_code=404)

    nuclei_agent_args.process(scan_message_domain)

    assert all("-t" not in c.args[0] for c in run_command_mock.call_args_list)


@mock.patch(
    "agent.agent_nuclei.OUTPUT_PATH", "./tests/result_nuclei_node2shell_brotli_fp.json"
)
def testAgentNuclei_whenNode2ShellBrotliTemplateMatches_shouldNotReport(
    scan_message: message.Message,
    nuclei_agent_no_url_scope: agent_nuclei.AgentNuclei,
    mocker: plugin.MockerFixture,
) -> None:
    """The upstream `CVE-2026-111497` template infers a Brotli decoder from response differences
    between control requests, which a host that never reads the request body also produces, so
    the finding is a known false positive and must not be reported."""
    mocker.patch("subprocess.run", return_value=None)
    mock_report_vulnerability = mocker.patch(
        "agent.agent_nuclei.AgentNuclei.report_vulnerability", return_value=None
    )

    nuclei_agent_no_url_scope.process(scan_message)

    assert mock_report_vulnerability.called is False


@mock.patch(
    "agent.agent_nuclei.OUTPUT_PATH", "./tests/result_nuclei_lgcookieslaw_fp.json"
)
def testAgentNuclei_whenLgcookieslawTemplateMatches_shouldNotReport(
    scan_message: message.Message,
    nuclei_agent_no_url_scope: agent_nuclei.AgentNuclei,
    mocker: plugin.MockerFixture,
) -> None:
    """Suppress both timing matchers from the upstream and KEV template copies."""
    mocker.patch("subprocess.run", return_value=None)
    mock_report_vulnerability = mocker.patch(
        "agent.agent_nuclei.AgentNuclei.report_vulnerability", return_value=None
    )

    nuclei_agent_no_url_scope.process(scan_message)

    mock_report_vulnerability.assert_not_called()
