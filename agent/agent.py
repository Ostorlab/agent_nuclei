"""Agent implementation for nuclei scanner."""
import ipaddress
import json
import logging
import pathlib
from urllib import parse
import subprocess
import tempfile
from os import path
from typing import Dict, List, Optional

import dataclasses
import requests

from ostorlab.agent import agent
from ostorlab.agent.message import message as m
from ostorlab.agent import definitions as agent_definitions
from ostorlab.agent.kb import kb
from ostorlab.agent.mixins import agent_persist_mixin
from ostorlab.agent.mixins import agent_report_vulnerability_mixin
from ostorlab.runtimes import definitions as runtime_definitions
from rich import logging as rich_logging

logging.basicConfig(
    format='%(message)s',
    datefmt='[%X]',
    handlers=[rich_logging.RichHandler(rich_tracebacks=True)],
    level='INFO',
    force=True
)
logger = logging.getLogger(__name__)

OUTPUT_PATH = '/tmp/result_nuclei.json'

SCHEME_TO_PORT = {'http': 80, 'https': 443}

NUCLEI_RISK_MAPPING = {
    'critical': agent_report_vulnerability_mixin.RiskRating.HIGH,
    'high': agent_report_vulnerability_mixin.RiskRating.HIGH,
    'medium': agent_report_vulnerability_mixin.RiskRating.MEDIUM,
    'low': agent_report_vulnerability_mixin.RiskRating.LOW,
    'info': agent_report_vulnerability_mixin.RiskRating.INFO,
}

STORAGE_NAME = 'agent_nuclei'


@dataclasses.dataclass
class Target:
    name: str
    schema: Optional[str] = None
    port: Optional[int] = None


class AgentNuclei(agent.Agent, agent_report_vulnerability_mixin.AgentReportVulnMixin,
                  agent_persist_mixin.AgentPersistMixin):
    """Nuclei agent."""

    def __init__(self,
                 agent_definition: agent_definitions.AgentDefinition,
                 agent_settings: runtime_definitions.AgentSettings) -> None:

        agent.Agent.__init__(self, agent_definition, agent_settings)
        agent_persist_mixin.AgentPersistMixin.__init__(self, agent_settings)
        agent_report_vulnerability_mixin.AgentReportVulnMixin.__init__(self)

    def process(self, message: m.Message) -> None:
        """Starts Nuclei scan wait for the scan to finish,
        and emit the results.

        Args:
            message: The message to process from ostorlab runtime

        Returns:

        """
        logger.info('processing message of selector : %s', message.selector)
        if self._is_target_already_processed(message) is False:
            return

        targets = self._prepare_targets(message)
        if len(targets) > 0:
            templates_urls = self.args.get('template_urls')
            if templates_urls is not None:
                self._run_templates(templates_urls, targets)
            if self.args.get('use_default_templates', True):
                self._run_command(targets)
        logger.info('Done processing message of selector : %s', message.selector)

    def _parse_output(self) -> None:
        """Parse Nuclei Json output and emit the findings as vulnerabilities"""
        with open(OUTPUT_PATH, 'r', encoding='UTF-8') as f:
            lines = f.readlines()
            for line in lines:
                nuclei_data_dict = json.loads(line)
                technical_detail = ''
                matcher_status = nuclei_data_dict.get('matcher-status', False)
                matcher_name = nuclei_data_dict.get('matcher-name', None)
                matched_at = nuclei_data_dict.get('matched-at')
                if matcher_status is True and matcher_name is not None:
                    technical_detail += f"""Matched : `{matcher_name}` at  [{matched_at}]({matched_at}) \n"""

                template_info = nuclei_data_dict['info']
                extracted_results = nuclei_data_dict.get('extracted-results', [])
                if len(extracted_results) > 0:
                    technical_detail += f"""### {template_info.get('name')}: \n"""
                    for value in extracted_results:
                        technical_detail += f"""* {value}\n"""

                curl_command = nuclei_data_dict.get('curl-command')
                if curl_command is not None:
                    technical_detail += f""" #### Reproduction `curl` command:  \n```bash\n{curl_command}\n``` \n """

                req_type = nuclei_data_dict.get('type')
                request = nuclei_data_dict.get('request')
                if request is not None:
                    technical_detail += f""" #### Request:  \n```{req_type}  \n{request}\n``` \n"""

                response = nuclei_data_dict.get('response')
                if response is not None:
                    technical_detail += f""" #### Response:  \n```{req_type}  \n{response}\n``` \n """
                nuclei_data_dict.pop('template', None)
                nuclei_data_dict.pop('template-id', None)
                nuclei_data_dict.pop('template-url', None)
                nuclei_data_dict.pop('request', None)
                nuclei_data_dict.pop('response', None)
                nuclei_data_dict.pop('curl-command', None)
                nuclei_data_dict['info'].pop('author', None)
                nuclei_data_dict['info'].pop('tags', None)
                scan_results = json.dumps(nuclei_data_dict, indent=4, sort_keys=True)
                technical_detail += f"""```json\n  {scan_results} \n ``` """

                severity = template_info.get('severity')

                self.report_vulnerability(
                    entry=kb.Entry(
                        title=template_info.get('name'),
                        risk_rating=str(NUCLEI_RISK_MAPPING[severity].value),
                        short_description=template_info.get('description', ''),
                        description=template_info.get('description', ''),
                        recommendation=template_info.get('recommendation', ''),
                        references=self._get_references(template_info),
                        security_issue=True,
                        privacy_issue=False,
                        has_public_exploit=False,
                        targeted_by_malware=False,
                        targeted_by_ransomware=False,
                        targeted_by_nation_state=False,
                        cvss_v3_vector=template_info.get('classification', {}).get('cvss-metrics', '')
                    ),
                    technical_detail=technical_detail,
                    risk_rating=NUCLEI_RISK_MAPPING[severity])

    def _get_references(self, template_info: Dict[str, Dict[str, List[str]]]) -> Dict[str, str]:
        """Generate dict references from nuclei references template"""
        references = {}
        cwe_list = template_info.get('classification', {}).get('cwe-id', [])
        if cwe_list is not None:
            for value in cwe_list:
                link = f"""https://nvd.nist.gov/vuln/detail/{value.replace('cwe-', '')}.html"""
                references[value] = link
        cve_list = template_info.get('classification', {}).get('cve-id', [])
        if cve_list is not None:
            for value in cve_list:
                value_link = f'https://cve.mitre.org/cgi-bin/cvename.cgi?name={value}'
                references[value] = value_link
        if template_info.get('reference') is not None:
            for value in template_info['reference']:
                references[value] = value
        return references

    def _run_templates(self, template_urls: List[str], targets: List[str]) -> None:
        """Run Nuclei scan on the provided templates"""
        templates = []
        with tempfile.TemporaryDirectory() as tmp_dir:
            file_path = pathlib.Path(tmp_dir)
            for url in template_urls:
                r = requests.get(url, allow_redirects=True, timeout=60)
                with (file_path / url.split('/')[-1]).open(mode='wb') as f:
                    f.write(r.content)
                templates.append((file_path / url.split('/')[-1]).name)

            if len(templates) > 0:
                self._run_command(targets, templates)

    def _is_target_already_processed(self, message: m.Message) -> bool:
        """Checks if the target has already been processed before, relies on the redis server."""
        if message.data.get('url') is not None or message.data.get('name') is not None:
            unicity_check_key: str = ''
            if message.data.get('url') is not None:
                target = self._get_target_from_url(message.data['url'])
                unicity_check_key = f'{target.schema}_{target.name}_{target.port}'
            elif message.data.get('name') is not None:
                port = self._get_port(message)
                schema = self._get_schema(message)
                domain = message.data['name']
                unicity_check_key = f'{schema}_{domain}_{port}'

            if self.set_add(b'agent_nuclei_asset', str(unicity_check_key)) is True:
                return True
            else:
                logger.info('target %s/ was processed before, exiting', unicity_check_key)
                return False
        elif message.data.get('host') is not None:
            host = str(message.data.get('host'))
            mask = message.data.get('mask')
            schema = self._get_schema(message)
            port = self._get_port(message)
            if mask is not None:
                addresses = ipaddress.ip_network(f'{host}/{mask}')
                result = self.add_ip_network('agent_nuclei_asset', addresses, lambda net: f'{schema}_{net}_{port}')
                if result is False:
                    logger.info('target %s was processed before, exiting', addresses)
            else:
                result = self.set_add('agent_nuclei_asset', f'{schema}_{host}_{port}')
                if result is False:
                    logger.info('target %s was processed before, exiting', host)
            return result
        else:
            logger.error('Unknown target %s', message)
            return True

    def _get_target_from_url(self, url: str) -> Target:
        """Compute schema and port from an URL"""
        parsed_url = parse.urlparse(url)
        schema = parsed_url.scheme or self.args.get('schema')
        domain_name = parse.urlparse(url).netloc
        port = 0
        if len(parsed_url.netloc.split(':')) > 1:
            domain_name = parsed_url.netloc.split(':')[0]
            if len(parsed_url.netloc.split(':')) > 0 and parsed_url.netloc.split(':')[-1] != '':
                port = int(parsed_url.netloc.split(':')[-1])
        port = port or int(str(SCHEME_TO_PORT.get(str(schema)))) or int(str(self.args.get('port')))
        target = Target(name=domain_name, schema=schema, port=port)
        return target

    def _get_port(self, message: m.Message) -> int:
        """Returns the port to be used for the target."""
        if message.data.get('port') is not None:
            return int(message.data['port'])
        else:
            return int(str(self.args.get('port')))

    def _get_schema(self, message: m.Message) -> str:
        """Returns the schema to be used for the target."""
        if message.data.get('schema') is not None:
            return str(message.data['schema'])
        elif message.data.get('protocol') is not None:
            return str(message.data['protocol'])
        elif self.args.get('https') is True:
            return 'https'
        else:
            return 'http'

    def _prepare_targets(self, message: m.Message) -> List[str]:
        """Prepare targets based on type, if a domain name is provided, port and protocol are collected from the config.
        """
        if message.data.get('host') is not None:
            host = str(message.data.get('host'))
            if message.data.get('mask') is None:
                ip_network = ipaddress.ip_network(host)
            else:
                mask = message.data.get('mask')
                ip_network = ipaddress.ip_network(f'{host}/{mask}')
            return [str(h) for h in ip_network.hosts()]
        elif message.data.get('name') is not None:
            domain_name = message.data.get('name')
            schema = self._get_schema(message)
            port = self.args.get('port')
            return [f'{schema}://{domain_name}:{port}']
        elif message.data.get('url') is not None:
            return [str(message.data.get('url'))]
        else:
            return []

    def _run_command(self, targets: List[str], templates: List[str] | None = None) -> None:
        """Run Nuclei command on the provided target using defined or default templates"""
        command = ['/nuclei/nuclei']
        for target in targets:
            command.extend(['-u', target])
        command.extend(['-json', '-irr', '-silent', '-o', OUTPUT_PATH])
        if templates is not None:
            for template in templates:
                if path.exists(template):
                    command.extend(['-t', template])

        subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)

        self._parse_output()


if __name__ == '__main__':
    logger.info('starting agent ...')
    AgentNuclei.main()
