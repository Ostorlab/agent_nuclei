"""Agent implementation for nuclei scanner."""
import subprocess
import json
import logging
from typing import Dict

from ostorlab.agent import agent
from ostorlab.agent import message as m
from ostorlab.agent.kb import kb
from ostorlab.agent.mixins import agent_report_vulnerability_mixin
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

NUCLEI_RISK_MAPPING = {
    'critical': agent_report_vulnerability_mixin.RiskRating.HIGH,
    'high': agent_report_vulnerability_mixin.RiskRating.HIGH,
    'medium': agent_report_vulnerability_mixin.RiskRating.MEDIUM,
    'low': agent_report_vulnerability_mixin.RiskRating.LOW,
    'info': agent_report_vulnerability_mixin.RiskRating.INFO,
}


class AgentNuclei(agent.Agent, agent_report_vulnerability_mixin.AgentReportVulnMixin):
    """Nuclei agent."""

    def process(self, message: m.Message) -> None:
        """Starts Nuclei scan wait for the scan to finish,
        and emit the results.

        Args:
            message: The message to process from ostorlab runtime

        Returns:

        """
        logger.info('processing message of selector : %s', message.selector)

        command = []
        if message.data.get('host') is not None:
            command = ['/nuclei/nuclei', '-u', message.data.get('host'), '-json', '-irr', '-silent', '-o', OUTPUT_PATH]
        elif message.data.get('name') is not None:
            command = ['/nuclei/nuclei', '-u', f'http://{message.data.get("name")}', '-u',
                       f'https://{message.data.get("name")}', '-json', '-irr', '-silent', '-o', OUTPUT_PATH]

        subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        self._parse_output()

    def _parse_output(self):
        """Parse Nuclei Json output and emit the findings as vulnerabilities"""
        with open(OUTPUT_PATH, 'r', encoding='UTF-8') as f:
            lines = f.readlines()
            for line in lines:
                nuclei_data_dict = json.loads(line)
                template_info = nuclei_data_dict['info']
                severity = template_info.get('severity')

                self.report_vulnerability(
                    entry=kb.Entry(
                        title=template_info.get('name'),
                        risk_rating=NUCLEI_RISK_MAPPING[severity].value,
                        short_description=template_info.get('description', ''),
                        description=template_info.get('description', ''),
                        recommendation=template_info.get('recommendation', ''),
                        references=self._get_references(template_info),
                        security_issue=True,
                        privacy_issue=False,
                        has_public_exploit=False,
                        targeted_by_malware=False,
                        targeted_by_ransomware=False,
                        targeted_by_nation_state=False
                    ),
                    technical_detail=f'```json\n{line}\n```',
                    risk_rating=NUCLEI_RISK_MAPPING[severity])

    def _get_references(self, template_info: Dict[str, str]) -> Dict[str, str]:
        """Generate dict references from nuclei references template"""
        if template_info.get('reference'):
            return {str(template_info.get('reference')): str(template_info.get('reference'))}
        else:
            return {}


if __name__ == '__main__':
    logger.info('starting agent ...')
    AgentNuclei.main()
