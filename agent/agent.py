"""Agent implementation for nuclei scanner."""
import subprocess
import json
import logging

from ostorlab.agent import agent
from ostorlab.agent import message as m
from ostorlab.agent.kb import kb
from ostorlab.agent.mixins import agent_report_vulnerability_mixin
from rich import logging as rich_logging


logging.basicConfig(
    format='%(message)s',
    datefmt='[%X]',
    handlers=[rich_logging.RichHandler(rich_tracebacks=True)]
)
logger = logging.getLogger(__name__)

OUTPUT_PATH = '/tmp/result_nuclei.json'

NUCLEI_RISK_MAPPING = {
    'critical': 'HIGH',
    'high': 'HIGH',
    'medium': 'MEDIUM',
    'low': 'LOW',
    'info': 'INFO',
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
        logger.info('Received a new message, processing...')
        command = ['/nuclei/nuclei', '-u', message.data['host'], '-json', '-irr', '-silent', '-o', OUTPUT_PATH]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        process.communicate()
        self._parse_output()

    def _parse_output(self):
        with open(OUTPUT_PATH, 'r') as f:
            lines = f.readlines()
            for line in lines:
                nuclei_data_dict = json.loads(line)
                template_info = nuclei_data_dict['info']
                severity = template_info.get('severity')
                self.report_vulnerability(
                    entry=kb.Entry(
                        title=template_info.get('name'),
                        risk_rating=NUCLEI_RISK_MAPPING[severity],
                        short_description=template_info.get('description', ''),
                        description=template_info.get('description', ''),
                        recommendation=template_info.get('recommendation', ''),
                        references={},
                        security_issue=True,
                        privacy_issue=False,
                        has_public_exploit=True,
                        targeted_by_malware=True,
                        targeted_by_ransomware=True,
                        targeted_by_nation_state=True
                    ),
                    technical_detail=f'```json\n{line}\n```',
                    risk_rating=NUCLEI_RISK_MAPPING[severity])
            logger.info('Scan finished Number of finding %s', len(lines))


if __name__ == '__main__':
    logger.info('starting agent ...')
    AgentNuclei.main()