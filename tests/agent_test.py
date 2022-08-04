"""Unittests for nuclei class."""
from unittest import mock

from ostorlab.agent.mixins import agent_report_vulnerability_mixin


@mock.patch('agent.agent.OUTPUT_PATH', './tests/result_nuclei.json')
def testAgentNuclei_whenBinaryAvailable_RunScan(scan_message, nuclei_agent, agent_persist_mock, mocker):
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
def testAgentNuclei_whenUrlTemplatesGivent_RunScan(requests_mock, scan_message, nuclei_agent_args, agent_persist_mock,
                                                   mocker):
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
def testAgentNuclei_whenLinkMessageAndBinaryAvailable_RunScan(scan_message_link, nuclei_agent,
                                                              agent_persist_mock, mocker):
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
def testAgentNuclei_whenTemplatesPrvided(requests_mock, scan_message, nuclei_agent_args, agent_persist_mock, mocker):
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


