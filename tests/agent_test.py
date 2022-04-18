"""Unittests for nuclei class."""
from unittest import mock

from ostorlab.agent import definitions as agent_definitions
from ostorlab.agent.mixins import agent_report_vulnerability_mixin
from ostorlab.runtimes import definitions as runtime_definitions
from ostorlab.utils import defintions as utils_definitions

from agent import agent


@mock.patch('agent.agent.OUTPUT_PATH', './tests/result_nuclei.json')
def testAgentNuclei_whenBinaryAvailable_RunScan(scan_message, mocker):
    """Tests running the agent and parsing the json output."""
    definition = agent_definitions.AgentDefinition(
        name='start_test_agent',
        out_selectors=[])
    settings = runtime_definitions.AgentSettings(
        key='agent/ostorlab/start_test_agent',
        bus_url='NA',
        bus_exchange_topic='NA',
        args=[],
        healthcheck_port=5301)
    mocker.patch('subprocess.run', return_value=None)
    mock_report_vulnerability = mocker.patch('agent.agent.AgentNuclei.report_vulnerability', return_value=None)
    test_agent = agent.AgentNuclei(definition, settings)
    test_agent.process(scan_message)
    mock_report_vulnerability.assert_called_once()
    assert mock_report_vulnerability.call_args.kwargs['entry'].cvss_v3_vector \
           == 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'
    assert """Matched : `ats` at""" in mock_report_vulnerability.call_args.kwargs['technical_detail']
    assert 'Author' not in mock_report_vulnerability.call_args.kwargs['technical_detail']
    assert mock_report_vulnerability.call_args.kwargs['risk_rating'] == agent_report_vulnerability_mixin.RiskRating.INFO


@mock.patch('agent.agent.OUTPUT_PATH', './tests/result_nuclei.json')
def testAgentNuclei_whenUrlTemplatesGivent_RunScan(scan_message, mocker):
    """Tests running the agent and parsing the json output."""
    definition = agent_definitions.AgentDefinition(
        name='start_test_agent',
        out_selectors=[])
    settings = runtime_definitions.AgentSettings(
        key='agent/ostorlab/start_test_agent',
        bus_url='NA',
        bus_exchange_topic='NA',
        args=[
            utils_definitions.Arg(
                name='custom_templates',
                type='str',
                value=[b'https://raw.githubusercontent.com/Knowledge/main/Cybertest/Web/CVE1.yaml',
                      b'https://github.com/test2//blob/main/Cybertest/Web/CVE2.yaml'])],
        healthcheck_port=5301)
    run_command_mock =  mocker.patch('subprocess.run', return_value=None)
    mock_report_vulnerability = mocker.patch('agent.agent.AgentNuclei.report_vulnerability', return_value=None)
    test_agent = agent.AgentNuclei(definition, settings)
    test_agent.process(scan_message)

    run_command_mock.assert_called()
    run_command_args= run_command_mock.call_args_list
    assert run_command_args[0][0][0] == ['/nuclei/nuclei', '-u', '209.235.136.112', '-json', '-irr',
                                         '-silent', '-o', './tests/result_nuclei.json']
    assert '/CVE1.yaml' in str(run_command_args[1][0][0][9])
    assert '/CVE2.yaml' in str(run_command_args[1][0][0][11])
    mock_report_vulnerability.assert_called()
