"""Unittests for nuclei class."""
from unittest import mock

from ostorlab.agent.mixins import agent_report_vulnerability_mixin

from agent import agent
from ostorlab.agent.kb import kb
from ostorlab.agent import definitions as agent_definitions
from ostorlab.runtimes import definitions as runtime_definitions
from ostorlab.utils import defintions as utils_definitions


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
        args=[
            utils_definitions.Arg(name='reporting_engine_base_url', type='str', value=b'https://toto.ostorlab.co/test'),
            utils_definitions.Arg(name='reporting_engine_token', type='str', value=b'123456')],
        healthcheck_port=5301)
    mocker.patch('subprocess.run',return_value=None)
    mock_report_vulnerability = mocker.patch('agent.agent.AgentNuclei.report_vulnerability', return_value=None)
    test_agent = agent.AgentNuclei(definition, settings)
    test_agent.process(scan_message)
    mock_report_vulnerability.assert_called_with(entry=kb.Entry(
        title='PTR Fingerprint', risk_rating=agent_report_vulnerability_mixin.RiskRating.INFO.value,
        short_description='', description='', recommendation='', references={},
        security_issue=True, privacy_issue=False, has_public_exploit=False, targeted_by_malware=False,
        targeted_by_ransomware=False, targeted_by_nation_state=False, cvss_v3_vector=''),
        technical_detail='```json\n{"template":"dns/ptr-fingerprint.yaml",'
                         '"template-url":"https://github.com/projectdiscovery/nuclei-templates/blob/master/dns/ptr'
                         '-fingerprint.yaml","template-id":"ptr-fingerprint","info":{"name":"PTR Fingerprint",'
                         '"author":["pdteam"],"tags":["dns","ptr"],"reference":null,"severity":"info"},"type":"dns",'
                         '"host":"209.235.136.112","matched-at":"209.235.136.112","extracted-results":['
                         '"web2012c1.megawebservers.com."],"request":";; opcode: QUERY, status: NOERROR, '
                         'id: 39958\\n;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1\\n\\n;; QUESTION '
                         'SECTION:\\n;112.136.235.209.in-addr.arpa.\\tIN\\t PTR\\n\\n;; ADDITIONAL SECTION:\\n\\n;; '
                         'OPT PSEUDOSECTION:\\n; EDNS: version 0; flags: ; udp: 4096\\n","response":";; opcode: '
                         'QUERY, status: NOERROR, id: 39958\\n;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, '
                         'ADDITIONAL: 1\\n\\n;; QUESTION SECTION:\\n;112.136.235.209.in-addr.arpa.\\tIN\\t '
                         'PTR\\n\\n;; ANSWER SECTION:\\n112.136.235.209.in-addr.arpa.\\t85104\\tIN\\tPTR\\tweb2012c1'
                         '.megawebservers.com.\\n\\n;; ADDITIONAL SECTION:\\n\\n;; OPT PSEUDOSECTION:\\n; EDNS: '
                         'version 0; flags: ; udp: 1232\\n","timestamp":"2022-02-17T13:54:42.424634426+01:00",'
                         '"matcher-status":true}\n\n```',
        risk_rating=agent_report_vulnerability_mixin.RiskRating.INFO)
