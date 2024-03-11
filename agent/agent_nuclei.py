"""Agent implementation for nuclei scanner."""

import dataclasses
import ipaddress
import json
import logging
import pathlib
import re
import subprocess
import tempfile
from os import path
from typing import Dict, List, Optional, cast
from urllib import parse
import base64

import requests
from ostorlab.agent import agent
from ostorlab.agent import definitions as agent_definitions
from ostorlab.agent.kb import kb
from ostorlab.agent.message import message as m
from ostorlab.agent.mixins import agent_persist_mixin
from ostorlab.agent.mixins import agent_report_vulnerability_mixin
from ostorlab.runtimes import definitions as runtime_definitions
from rich import logging as rich_logging

from agent import formatters
from agent import helpers
from agent.vpn import wg_vpn

FINDING_MAX_SIZE = 4096

logging.basicConfig(
    format="%(message)s",
    datefmt="[%X]",
    handlers=[rich_logging.RichHandler(rich_tracebacks=True)],
    level="INFO",
    force=True,
)
logger = logging.getLogger(__name__)

OUTPUT_PATH = "/tmp/result_nuclei.json"

SCHEME_TO_PORT = {"http": 80, "https": 443}

NUCLEI_RISK_MAPPING = {
    "critical": agent_report_vulnerability_mixin.RiskRating.CRITICAL,
    "high": agent_report_vulnerability_mixin.RiskRating.HIGH,
    "medium": agent_report_vulnerability_mixin.RiskRating.MEDIUM,
    "low": agent_report_vulnerability_mixin.RiskRating.LOW,
    "info": agent_report_vulnerability_mixin.RiskRating.INFO,
    "unknown": agent_report_vulnerability_mixin.RiskRating.INFO,
}

STORAGE_NAME = "agent_nuclei"
MAX_TARGETS_COMMAND_LINE = 10
IPV4_CIDR_LIMIT = 16
IPV6_CIDR_LIMIT = 112


@dataclasses.dataclass
class Target:
    name: str
    schema: Optional[str] = None
    port: Optional[int] = None


@dataclasses.dataclass
class BasicCredential:
    """Credential for basic authentication passing password and login."""

    def __init__(self, login: str, password: str) -> None:
        self.login = login
        self.password = password

    @property
    def header(self) -> str:
        credentials = f"{self.login}:{self.password}"

        encoded_credentials = base64.b64encode(credentials.encode("utf-8")).decode(
            "utf-8"
        )

        auth_header = f"Authorization: Basic {encoded_credentials}"
        return auth_header


def build_basic_credential_from_message(
    message: m.Message,
) -> list[BasicCredential]:
    basic_credential = message.data.get("basic_credential")
    if basic_credential is None:
        return []
    login = basic_credential.get("login")
    if login is None:
        return []
    password = basic_credential.get("password")
    if password is None:
        return []
    return [BasicCredential(login=login, password=password)]


def build_basic_credential_from_args(
    basic_credentials: list[dict[str, str]] | None,
) -> list[BasicCredential]:
    if basic_credentials is None:
        return []
    credentials = []
    for credential in basic_credentials:
        credentials.append(
            BasicCredential(
                login=credential["login"],
                password=credential["password"],
            )
        )
    return credentials


class AgentNuclei(
    agent.Agent,
    agent_report_vulnerability_mixin.AgentReportVulnMixin,
    agent_persist_mixin.AgentPersistMixin,
):
    """Nuclei agent."""

    def __init__(
        self,
        agent_definition: agent_definitions.AgentDefinition,
        agent_settings: runtime_definitions.AgentSettings,
    ) -> None:
        agent.Agent.__init__(self, agent_definition, agent_settings)
        agent_persist_mixin.AgentPersistMixin.__init__(self, agent_settings)
        agent_report_vulnerability_mixin.AgentReportVulnMixin.__init__(self)
        self._scope_urls_regex: str | None = self.args.get("scope_urls_regex")
        self._vpn_config: str | None = self.args.get("vpn_config")
        self._dns_config: str | None = self.args.get("dns_config")
        self._basic_credentials: list[BasicCredential] = []
        self._proxy: str | None = self.args.get("proxy")

    def start(self) -> None:
        """Enable VPN configuration at the beginning if needed."""
        wg_vpn.enable_vpn_connection(
            vpn_config=self._vpn_config, dns_config=self._dns_config
        )

    def process(self, message: m.Message) -> None:
        """Starts Nuclei scan wait for the scan to finish,
        and emit the results.

        Args:
            message: The message to process from ostorlab runtime

        Returns:

        """
        logger.debug("processing message of selector : %s", message.selector)
        if self._is_target_already_processed(message) is True:
            return

        logger.info("Preparing targets.")
        targets = self.prepare_targets(message)
        # Filter out all the target that are out of scope.
        targets = [
            t
            for t in targets
            if self._should_process_target(self._scope_urls_regex, t) is True
        ]

        logger.info("Scanning targets `%s`.", targets)

        self._basic_credentials = build_basic_credential_from_message(
            message
        ) or build_basic_credential_from_args(self.args.get("basic_credentials"))
        if len(targets) > 0:
            templates_urls = self.args.get("template_urls")
            if templates_urls is not None:
                logger.info("Running custom templates.")
                self._run_templates(templates_urls, targets)
            if self.args.get("use_default_templates", True):
                logger.info("Running default templates.")
                self._run_command(targets)
        self._mark_target_as_processed(message)
        logger.debug("Done processing message of selector : %s", message.selector)

    def _parse_output(self) -> None:
        """Parse Nuclei Json output and emit the findings as vulnerabilities"""
        with open(OUTPUT_PATH, "r", encoding="UTF-8") as f:
            lines = f.readlines()
            for line in lines:
                nuclei_data_dict = json.loads(line)
                technical_detail = ""
                matcher_status = nuclei_data_dict.get("matcher-status", False)
                matcher_name = nuclei_data_dict.get("matcher-name", None)
                matched_at = nuclei_data_dict.get("matched-at")
                if matcher_status is True and matcher_name is not None:
                    technical_detail += (
                        f"""Matched : `{matcher_name}` at `{matched_at}`\n"""
                    )

                template_info = nuclei_data_dict["info"]
                extracted_results = nuclei_data_dict.get("extracted-results", [])
                if len(extracted_results) > 0:
                    technical_detail += f"""### {template_info.get('name')}: \n"""
                    for value in extracted_results:
                        technical_detail += f"""* {value}\n"""

                curl_command = nuclei_data_dict.get("curl-command")
                if curl_command is not None:
                    technical_detail += f""" #### Reproduction `curl` command:  \n```bash\n{curl_command}\n``` \n """

                req_type = nuclei_data_dict.get("type")
                request = nuclei_data_dict.get("request")
                if request is not None:
                    truncated_request = formatters.truncate(
                        value=request, truncate_size=FINDING_MAX_SIZE
                    )
                    technical_detail += f""" #### Request:  \n```{req_type}  \n{truncated_request}\n``` \n"""

                response = nuclei_data_dict.get("response")
                if response is not None:
                    truncated_reponse = formatters.truncate(
                        value=response, truncate_size=FINDING_MAX_SIZE
                    )
                    technical_detail += f""" #### Response:  \n```{req_type}  \n{truncated_reponse}\n``` \n """

                nuclei_data_dict.pop("template", None)
                nuclei_data_dict.pop("template-id", None)
                nuclei_data_dict.pop("template-url", None)
                nuclei_data_dict.pop("request", None)
                nuclei_data_dict.pop("response", None)
                nuclei_data_dict.pop("curl-command", None)
                nuclei_data_dict["info"].pop("author", None)
                nuclei_data_dict["info"].pop("tags", None)

                minified_data_dict = formatters.minify_dict(
                    nuclei_data_dict, formatters.truncate
                )
                scan_results = json.dumps(minified_data_dict, indent=4, sort_keys=True)
                technical_detail += f"""```json\n  {scan_results} \n ``` """

                severity = template_info.get("severity")

                vuln_location = helpers.build_vuln_location(matched_at)

                self.report_vulnerability(
                    entry=kb.Entry(
                        title=template_info.get("name"),
                        risk_rating=str(NUCLEI_RISK_MAPPING[severity].value),
                        short_description=template_info.get("description", ""),
                        description=template_info.get("description", ""),
                        recommendation=template_info.get("recommendation", ""),
                        references=self._get_references(template_info),
                        security_issue=True,
                        privacy_issue=False,
                        has_public_exploit=False,
                        targeted_by_malware=False,
                        targeted_by_ransomware=False,
                        targeted_by_nation_state=False,
                        cvss_v3_vector=template_info.get("classification", {}).get(
                            "cvss-metrics", ""
                        ),
                    ),
                    vulnerability_location=vuln_location,
                    technical_detail=technical_detail,
                    risk_rating=NUCLEI_RISK_MAPPING[severity],
                )

    def _get_references(
        self, template_info: Dict[str, Dict[str, List[str]]]
    ) -> Dict[str, str]:
        """Generate dict references from nuclei references template"""
        references = {}
        cwe_list = template_info.get("classification", {}).get("cwe-id", [])
        if cwe_list is not None:
            for value in cwe_list:
                link = f"""https://nvd.nist.gov/vuln/detail/{value.replace('cwe-', '')}.html"""
                references[value] = link
        cve_list = template_info.get("classification", {}).get("cve-id", [])
        if cve_list is not None:
            for value in cve_list:
                value_link = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={value}"
                references[value] = value_link
        if template_info.get("reference") is not None:
            for value in template_info["reference"]:
                references[value] = value
        return references

    def _run_templates(self, template_urls: List[str], targets: List[str]) -> None:
        """Run Nuclei scan on the provided templates"""
        templates = []
        with tempfile.TemporaryDirectory() as tmp_dir:
            file_path = pathlib.Path(tmp_dir)
            for url in template_urls:
                r = requests.get(url, allow_redirects=True, timeout=60)
                with (file_path / url.split("/")[-1]).open(mode="wb") as f:
                    f.write(r.content)
                templates.append(str((file_path / url.split("/")[-1])))

            if len(templates) > 0:
                self._run_command(targets, templates)

    def _is_target_already_processed(self, message: m.Message) -> bool:
        """Checks if the target has already been processed before, relies on the redis server."""
        if message.data.get("url") is not None or message.data.get("name") is not None:
            unicity_check_key = self._get_unique_check_key(message)
            if unicity_check_key is None:
                return True

            return self.set_is_member("agent_nuclei_asset", unicity_check_key)
        elif message.data.get("host") is not None:
            host = str(message.data.get("host"))
            mask = message.data.get("mask")
            if mask is not None:
                addresses = ipaddress.ip_network(f"{host}/{mask}", strict=False)
                return self.ip_network_exists("agent_nuclei_asset", addresses)
            else:
                return self.set_is_member("agent_nuclei_asset", host)
        else:
            logger.error("Unknown target %s", message)
            return True

    def _mark_target_as_processed(self, message: m.Message) -> None:
        """Mark the target as processed, relies on the redis server."""
        if message.data.get("url") is not None or message.data.get("name") is not None:
            unicity_check_key = self._get_unique_check_key(message)
            if unicity_check_key is None:
                return

            self.set_add("agent_nuclei_asset", unicity_check_key)
        elif message.data.get("host") is not None:
            host = str(message.data.get("host"))
            mask = message.data.get("mask")
            if mask is not None:
                addresses = ipaddress.ip_network(f"{host}/{mask}", strict=False)
                self.add_ip_network("agent_nuclei_asset", addresses)
            else:
                self.set_add("agent_nuclei_asset", host)
        else:
            logger.error("Unknown target %s", message)
            return

    def _get_unique_check_key(self, message: m.Message) -> str | None:
        """Compute a unique key for a target"""
        if message.data.get("url") is not None:
            target = self._get_target_from_url(message)
            if target is not None:
                return f"{target.schema}_{target.name}_{target.port}"
        elif message.data.get("name") is not None:
            port = self._get_port(message)
            schema = self._get_schema(message)
            domain = message.data["name"]
            return f"{schema}_{domain}_{port}"
        return None

    def _get_target_from_url(self, message: m.Message) -> Target | None:
        """Compute schema and port from a URL"""
        url = message.data["url"]
        parsed_url = parse.urlparse(url)
        if parsed_url.scheme not in SCHEME_TO_PORT:
            return None
        schema = parsed_url.scheme or self.args.get("schema")
        schema = cast(str, schema)
        domain_name = parse.urlparse(url).netloc
        port = 0
        if len(parsed_url.netloc.split(":")) > 1:
            domain_name = parsed_url.netloc.split(":")[0]
            if (
                len(parsed_url.netloc.split(":")) > 0
                and parsed_url.netloc.split(":")[-1] != ""
            ):
                port = int(parsed_url.netloc.split(":")[-1])
        args_port = self._get_port(message)
        port = port or SCHEME_TO_PORT.get(schema) or args_port
        target = Target(name=domain_name, schema=schema, port=port)
        return target

    def _get_port(self, message: m.Message) -> int:
        """Returns the port to be used for the target."""
        if message.data.get("port") is not None:
            return int(message.data["port"])
        else:
            return int(str(self.args.get("port")))

    def _get_schema(self, message: m.Message) -> str:
        """Returns the schema to be used for the target."""
        if message.data.get("schema") is not None:
            if str(message.data["schema"]) in [
                "https?",
                "ssl/https-alt?",
                "ssl/https-alt",
                "https-alt",
                "https-alt?",
            ]:
                return "https"
            else:
                return str(message.data["schema"])
        elif message.data.get("protocol") is not None:
            return str(message.data["protocol"])
        elif self.args.get("https") is True:
            return "https"
        else:
            return "http"

    def prepare_targets(self, message: m.Message) -> List[str]:
        """Prepare targets based on type, if a domain name is provided, port and protocol are collected
        from the config.

        Args:
            message (m.Message): The input message containing information about the target.

        Returns:
            List: A list of targets containing host, port, and scheme information.
        """
        if message.data.get("host") is not None:
            host = str(message.data.get("host"))
            mask = message.data.get("mask")
            if mask is None:
                ip_network = ipaddress.ip_network(host)
            else:
                version = message.data.get("version")
                if version == 4 and int(mask) < IPV4_CIDR_LIMIT:
                    raise ValueError(
                        f"Subnet mask below {IPV4_CIDR_LIMIT} is not supported."
                    )
                if version == 6 and int(mask) < IPV6_CIDR_LIMIT:
                    raise ValueError(
                        f"Subnet mask below {IPV6_CIDR_LIMIT} is not supported."
                    )
                ip_network = ipaddress.ip_network(f"{host}/{mask}", strict=False)
            return [str(h) for h in ip_network.hosts()]

        elif (domain_name := message.data.get("name")) is not None:
            schema = self._get_schema(message)
            port = self._get_port(message)
            if schema == "https" and port not in [443, None]:
                url = f"https://{domain_name}:{port}"
            elif schema == "https":
                url = f"https://{domain_name}"
            elif port == 80:
                url = f"http://{domain_name}"
            elif port is None:
                url = f"{schema}://{domain_name}"
            else:
                url = f"{schema}://{domain_name}:{port}"

            return [url]

        elif (url_temp := message.data.get("url")) is not None:
            return [url_temp]
        else:
            return []

    def _run_command(
        self, targets: List[str], templates: List[str] | None = None
    ) -> None:
        """Run Nuclei command on the provided target using defined or default templates"""
        chunks = [
            targets[x : x + MAX_TARGETS_COMMAND_LINE]
            for x in range(0, len(targets), MAX_TARGETS_COMMAND_LINE)
        ]
        for chunk in chunks:
            command = ["/nuclei/nuclei"]
            if self._proxy is not None:
                command.extend(["-proxy", self._proxy])
            for item in chunk:
                command.extend(["-u", item])
            command.extend(["-j", "-irr", "-silent", "-o", OUTPUT_PATH])
            if templates is not None:
                for template in templates:
                    if path.exists(template):
                        command.extend(["-t", template])

            if len(self._basic_credentials) == 0:
                self._run_nuclei_command(command)
            else:
                for basic_credential in self._basic_credentials:
                    self._run_nuclei_command([*command, "-H", basic_credential.header])

    def _run_nuclei_command(self, command: list[str]) -> None:
        try:
            subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            )
            logger.info("Parsing nuclei output.")
            self._parse_output()
        except subprocess.CalledProcessError as e:
            logger.error("Error running nuclei %s", e)

    def _should_process_target(self, scope_urls_regex: Optional[str], url: str) -> bool:
        if scope_urls_regex is None:
            return True
        link_in_scan_domain = re.match(scope_urls_regex, url) is not None
        if not link_in_scan_domain:
            logger.warning("link url %s is not in domain %s", url, scope_urls_regex)
        return link_in_scan_domain


if __name__ == "__main__":
    logger.info("starting agent ...")
    AgentNuclei.main()
