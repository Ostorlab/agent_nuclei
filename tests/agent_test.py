"""Unittests for nuclei class."""
from unittest import mock
import subprocess

from agent import agent
from ostorlab.agent import definitions as agent_definitions
from ostorlab.runtimes import definitions as runtime_definitions
from ostorlab.utils import defintions as utils_definitions


@mock.patch('agent.agent.OUTPUT_PATH', './result_nuclei.json')
def testAgentNuclei_whenBinaryAvailable_RunScan(scan_message, mocker):
    """Tests running the agent and parsing the json output."""
    definition = agent_definitions.AgentDefinition(
        name='start_test_agent',
        out_selectors=[])
    settings = runtime_definitions.AgentSettings(
        key='agent/ostorlab/start_test_agent',
        bus_url='NA',
        bus_exchange_topic='NA',
        args=[
            utils_definitions.Arg(name='reporting_engine_base_url', type='str', value=b'https://toto.ostorlab.co/test'),
            utils_definitions.Arg(name='reporting_engine_token', type='str', value=b'123456')],
        healthcheck_port=5301)
    mocker.patch('subprocess.Popen',
                 return_value=subprocess.Popen('ls'))
    mocker.patch('subprocess.Popen.communicate', return_value=None)
    mock_report_vulnerability = mocker.patch('agent.agent.AgentNuclei.report_vulnerability', return_value=None)
    test_agent = agent.AgentNuclei(definition, settings)
    test_agent.process(scan_message)
    assert mock_report_vulnerability.called
