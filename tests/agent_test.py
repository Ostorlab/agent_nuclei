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
    mocker.patch('subprocess.run', return_value=None)
    mock_report_vulnerability = mocker.patch('agent.agent.AgentNuclei.report_vulnerability', return_value=None)
    test_agent = agent.AgentNuclei(definition, settings)
    test_agent.process(scan_message)
    mock_report_vulnerability.assert_called_with(
        entry=kb.Entry(
            title='CLink Office v2 XSS',
            risk_rating=agent_report_vulnerability_mixin.RiskRating.MEDIUM.value,
            short_description='A cross-site scripting (XSS) vulnerability inthe index page of the CLink Office 2.0 '
                              'management console allows remote attackers to inject arbitrary web script or HTML'
                              ' via the lang parameter.\n',
            description='A cross-site scripting (XSS) vulnerability inthe '
                        'index page of the CLink Office 2.0 management '
                        'console allows remote attackers to inject arbitrary web'
                        ' script or HTML via the lang parameter.\n',
            recommendation='',
            references={'cwe-79': 'https://nvd.nist.gov/vuln/detail/79.html',
                        'cve-2020-6171': 'https://cve.mitre.org/cgi-bin/cvename.cgi?'
                                         'name=cve-2020-6171',
                        'https://nvd.nist.gov/vuln/detail/cve-2020-6171': 'https://nvd.nist.g'
                                                                          'ov/vuln/detail/cve-2020-6171'}
            ,
            security_issue=True,
            privacy_issue=False,
            has_public_exploit=False,
            targeted_by_malware=False,
            targeted_by_ransomware=False,
            targeted_by_nation_state=False,
            cvss_v3_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'),
        technical_detail='## Details: \n'
                         ' ## Host details : \n'
                         ' * Host: '
                         '[https://onlinerestaurants.com](https://onlinerestaurants.com) \n'
                         ' * Ip address: [50.18.113.127](50.18.113.127) \n'
                         ' #### Curl command  \n'
                         '```bash\n'
                         "curl -X 'GET' -d '' -H 'Accept: */*' -H "
                         "'Accept-Language: en' -H 'User-Agent: Mozilla/5.0 "
                         '(Macintosh; Intel Mac OS X 10_8_4) AppleWebKit/537.36 '
                         '(KHTML, like Gecko) Chrome/49.0.2656.18 '
                         "Safari/537.36''https://onlinerestaurants.com?lang=%22%3E%3C%2Fs"
                         "cript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E%3Cp%20class=%22&p=1'\n"
                         '``` \n'
                         '  #### Request  \n'
                         '```http  \n'
                         'GET '
                         '/?lang=%22%3E%3C%2Fscript%3E%3Cscript%3Ealert%28document.'
                         'domain%29%3C%2Fscript%3E%3Cp%20class=%22&p=1 '
                         'HTTP/1.1\r\n'
                         'Host: onlinerestaurants.com\r\n'
                         'User-Agent: Mozilla/5.0 (Macintosh; Intel MacOS X '
                         '10_8_4) AppleWebKit/537.36 (KHTML, like Gecko) '
                         'Chrome/49.0.2656.18 Safari/537.36\r\n'
                         'Connection: close\r\n'
                         'Accept: */*\r\n'
                         'Accept-Language: en\r\n'
                         'Accept-Encoding:gzip\r\n'
                         '\r\n'
                         '\n'
                         '``` \n'
                         ' #### Response  \n'
                         '```http  \n'
                         'HTTP/1.1 200 OK\r\n'
                         'Connection:\n'
                         '``` \n'
                         '  ```json\n'
                         '  {\n'
                         '    "curl-command": "curl -X \'GET\' -d \'\' -H '
                         "'Accept: */*' -H 'Accept-Language: en' -H 'User-Agent: "
                         'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_4) '
                         'AppleWebKit/537.36 (KHTML, like Gecko) '
                         'Chrome/49.0.2656.18 '
                         'Safari/537.36\'\'https://onlinerestaurants.com?'
                         'lang=%22%3E%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29'
                         '%3C%2Fscript%3E%3Cp%20class=%22&p=1\'",\n'
                         '    "host": "https://onlinerestaurants.com",\n'
                         '    "info": {\n'
                         '        "author": [\n'
                         '            "pikpikcu"\n'
                         '        ],\n'
                         '        "classification": {\n'
                         '            "cve-id": [\n'
                         '                "cve-2020-6171"\n'
                         '            ],\n'
                         '            "cvss-metrics": '
                         '"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",\n'
                         '            "cvss-score": 6.1,\n'
                         '            "cwe-id": [\n'
                         '                "cwe-79"\n'
                         '            ]\n'
                         '        },\n'
                         '        "description": "A cross-site scripting (XSS) '
                         'vulnerability inthe index page of the CLink Office 2.0 '
                         'management console allows remote attackers to inject '
                         'arbitrary web script or HTML via the lang '
                         'parameter.\\n",\n'
                         '        "name": "CLink Office v2 XSS",\n'
                         '        "reference": [\n'
                         '            '
                         '"https://nvd.nist.gov/vuln/detail/cve-2020-6171"\n'
                         '        ],\n'
                         '        "severity": "medium",\n'
                         '        "tags": [\n'
                         '            "cve",\n'
                         '            "cve2020",\n'
                         '            "xss",\n'
                         '            "clink-office"\n'
                         '        ]\n'
                         '    },\n'
                         '    "ip": "50.18.113.127",\n'
                         '    "matched-at": '
                         '"https://onlinerestaurants.com?lang=%22%3E%3C%2Fscript%3E%3Cscript%3Ealert%28documen'
                         't.domain%29%3C%2Fscript%3E%3Cp%20class=%22&p=1",\n'
                         '    "matcher-status": true,\n'
                         '    "request": "GET '
                         '/?lang=%22%3E%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29'
                         '%3C%2Fscript%3E%3Cp%20class=%22&p=1 '
                         'HTTP/1.1\\r\\nHost: '
                         'onlinerestaurants.com\\r\\nUser-Agent: Mozilla/5.0 '
                         '(Macintosh; Intel MacOS X 10_8_4) AppleWebKit/537.36 '
                         '(KHTML, like Gecko) Chrome/49.0.2656.18 '
                         'Safari/537.36\\r\\nConnection: close\\r\\nAccept: '
                         '*/*\\r\\nAccept-Language: '
                         'en\\r\\nAccept-Encoding:gzip\\r\\n\\r\\n",\n'
                         '    "response": "HTTP/1.1 200 OK\\r\\nConnection:",\n'
                         '    "timestamp": "2022-03-28T11:16:38.706668609Z",\n'
                         '    "type": "http"\n'
                         '} \n'
                         ' ``` ',
        risk_rating=agent_report_vulnerability_mixin.RiskRating.MEDIUM)
