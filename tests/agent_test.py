"""Unittests for nuclei class."""
from unittest import mock
from typing import Dict

import requests_mock as rq_mock
from ostorlab.agent.message import message
from ostorlab.agent.mixins import agent_report_vulnerability_mixin
from pytest_mock import plugin

from agent import agent

@mock.patch('agent.agent.OUTPUT_PATH', './tests/result_nuclei.json')
def testAgentNuclei_whenBinaryAvailable_RunScan(scan_message: message.Message,
                                                nuclei_agent: agent.AgentNuclei,
                                                agent_persist_mock: Dict[str | bytes, str | bytes],
                                                mocker: plugin.MockerFixture) -> None:
    """Tests running the agent and parsing the json output."""
    mocker.patch('subprocess.run', return_value=None)
    mock_report_vulnerability = mocker.patch('agent.agent.AgentNuclei.report_vulnerability', return_value=None)
    nuclei_agent.process(scan_message)
    mock_report_vulnerability.assert_called_once()
    assert mock_report_vulnerability.call_args.kwargs['entry'].cvss_v3_vector \
           == 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'
    assert """Matched : `ats` at""" in mock_report_vulnerability.call_args.kwargs['technical_detail']
    assert 'Author' not in mock_report_vulnerability.call_args.kwargs['technical_detail']
    assert mock_report_vulnerability.call_args.kwargs['risk_rating'] == agent_report_vulnerability_mixin.RiskRating.INFO


@mock.patch('agent.agent.OUTPUT_PATH', './tests/result_nuclei.json')
def testAgentNuclei_whenUrlTemplatesGiven_RunScan(requests_mock: rq_mock.mocker.Mocker,
                                                  scan_message: message.Message,
                                                  nuclei_agent_args: agent.AgentNuclei,
                                                  agent_persist_mock: Dict[str | bytes, str | bytes],
                                                  mocker: plugin.MockerFixture) -> None:
    """Tests running the agent and parsing the json output."""
    run_command_mock = mocker.patch('subprocess.run', return_value=None)
    mocker.patch('os.path.exists', return_value=True)
    requests_mock.get('https://raw.githubusercontent.com/Ostorlab/main/templates/CVE1.yaml', content=b'test1')
    requests_mock.get('https://raw.githubusercontent.com/Ostorlab/main/templates/CVE2.yaml', content=b'test2')
    mock_report_vulnerability = mocker.patch('agent.agent.AgentNuclei.report_vulnerability', return_value=None)
    nuclei_agent_args.process(scan_message)

    run_command_mock.assert_called()
    run_command_args = run_command_mock.call_args_list
    assert run_command_args[1][0][0] == ['/nuclei/nuclei', '-u', '209.235.136.112', '-json', '-irr',
                                         '-silent', '-o', './tests/result_nuclei.json']

    assert run_command_args[0].args == (['/nuclei/nuclei', '-u', '209.235.136.112', '-json', '-irr', '-silent', '-o',
                                         './tests/result_nuclei.json', '-t', 'CVE1.yaml', '-t', 'CVE2.yaml'],)
    mock_report_vulnerability.assert_called()


@mock.patch('agent.agent.OUTPUT_PATH', './tests/result_nuclei.json')
def testAgentNuclei_whenLinkMessageAndBinaryAvailable_RunScan(scan_message_link: message.Message,
                                                              nuclei_agent: agent.AgentNuclei,
                                                              agent_persist_mock: Dict[str | bytes, str | bytes],
                                                              mocker: plugin.MockerFixture) -> None:
    """Tests running the agent and parsing the json output."""
    mocker.patch('subprocess.run', return_value=None)
    mock_report_vulnerability = mocker.patch('agent.agent.AgentNuclei.report_vulnerability', return_value=None)
    nuclei_agent.process(scan_message_link)
    mock_report_vulnerability.assert_called_once()
    assert mock_report_vulnerability.call_args.kwargs['entry'].cvss_v3_vector \
           == 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'
    assert """Matched : `ats` at""" in mock_report_vulnerability.call_args.kwargs['technical_detail']
    assert 'Author' not in mock_report_vulnerability.call_args.kwargs['technical_detail']
    assert mock_report_vulnerability.call_args.kwargs['risk_rating'] == agent_report_vulnerability_mixin.RiskRating.INFO


@mock.patch('agent.agent.OUTPUT_PATH', './tests/result_nuclei.json')
def testAgentNuclei_whenTemplatesProvided(requests_mock: rq_mock.mocker.Mocker,
                                          scan_message: message.Message,
                                          nuclei_agent_args: agent.AgentNuclei,
                                          agent_persist_mock: Dict[str | bytes, str | bytes],
                                          mocker: plugin.MockerFixture) -> None:
    """Tests running the agent and parsing the json output."""
    run_command_mock = mocker.patch('subprocess.run', return_value=None)
    mocker.patch('os.path.exists', return_value=True)
    requests_mock.get('https://raw.githubusercontent.com/Ostorlab/main/templates/CVE1.yaml', content=b'test1')
    requests_mock.get('https://raw.githubusercontent.com/Ostorlab/main/templates/CVE2.yaml', content=b'test2')
    mocker.patch('agent.agent.AgentNuclei.report_vulnerability', return_value=None)
    nuclei_agent_args.process(scan_message)
    run_command_mock.assert_called()
    run_command_args = run_command_mock.call_args_list
    assert run_command_args[0].args == (['/nuclei/nuclei', '-u', '209.235.136.112', '-json', '-irr', '-silent', '-o',
                                         './tests/result_nuclei.json', '-t', 'CVE1.yaml', '-t', 'CVE2.yaml'],)
    assert run_command_args[1].args == (['/nuclei/nuclei', '-u', '209.235.136.112', '-json', '-irr', '-silent', '-o',
                                         './tests/result_nuclei.json'],)


@mock.patch('agent.agent.OUTPUT_PATH', './tests/result_nuclei.json')
def testAgentNuclei_whenMessageIsIpRange_scanMultipleTargets(requests_mock: rq_mock.mocker.Mocker,
                                                             scan_message_network_range: message.Message,
                                                             nuclei_agent: agent.AgentNuclei,
                                                             agent_persist_mock: Dict[str | bytes, str | bytes],
                                                             mocker: plugin.MockerFixture) -> None:
    """Tests running the agent and parsing the json output."""
    run_command_mock = mocker.patch('subprocess.run', return_value=None)
    mocker.patch('os.path.exists', return_value=True)
    requests_mock.get('https://raw.githubusercontent.com/Ostorlab/main/templates/CVE1.yaml', content=b'test1')
    requests_mock.get('https://raw.githubusercontent.com/Ostorlab/main/templates/CVE2.yaml', content=b'test2')
    mocker.patch('agent.agent.AgentNuclei.report_vulnerability', return_value=None)
    nuclei_agent.process(scan_message_network_range)
    run_command_mock.assert_called()
    run_command_args = run_command_mock.call_args_list
    assert '209.235.136.113' in run_command_args[0].args[0]
    assert '209.235.136.126' in run_command_args[0].args[0]
    assert '209.235.136.126' in run_command_args[0].args[0]
