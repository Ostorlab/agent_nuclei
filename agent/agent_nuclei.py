"""Agent implementation for nuclei scanner."""

import base64
import concurrent.futures
import dataclasses
import email.utils
import hashlib
import ipaddress
import json
import logging
import pathlib
import re
import subprocess
import tempfile
import threading
import time
from os import path
from typing import Any, cast
from urllib import parse

import requests
from ostorlab.agent import agent
from ostorlab.agent import definitions as agent_definitions
from ostorlab.agent.kb import kb
from ostorlab.agent.message import message as m
from ostorlab.agent.mixins import agent_persist_mixin, agent_report_vulnerability_mixin
from ostorlab.runtimes import definitions as runtime_definitions
from rich import logging as rich_logging

from agent import formatters, helpers
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
TEMPLATE_DOWNLOAD_WORKERS = 16
TEMPLATE_DOWNLOAD_TIMEOUT_SECONDS = 60
TEMPLATE_DOWNLOAD_RETRIES = 2
TEMPLATE_DOWNLOAD_BACKOFF_SECONDS = 2
DEFAULT_MAX_HOST_ERROR = 10
DEFAULT_REQUEST_TIMEOUT_SECONDS = 7
DEFAULT_REQUEST_RETRIES = 1
NUCLEI_TIMEOUT_MINUTES = 30
NUCLEI_TIMEOUT_SECONDS = NUCLEI_TIMEOUT_MINUTES * 60

# Known false-positive (template-id, matcher-name) pairs. Some upstream nuclei templates match
# generic page content on any host (e.g. any HTML form, or a common server banner), including
# third-party pages the scan reaches through redirects. Such a match is not a signal about the
# scanned asset, so the finding is suppressed agent-side. matcher-name is None for templates
# whose matcher is unnamed (nuclei omits it from the JSON output in silent mode).
# CVE-2026-111497 (node2shell) infers a Brotli decoder from response differences between control
# requests, which a static host or a CDN that never reads the request body also produces.
# CVE-2022-44727 trusts a weak lgcookieslaw fingerprint and a single slow request.
# dns-waf-detect's cloudflare matcher fires whenever the DNS answer carries a Cloudflare
# nameserver (`ns.cloudflare.com`), which only shows that Cloudflare is the authoritative DNS
# host and says nothing about a web application firewall being active.
# google-client-id flags Google OAuth client IDs, which are public identifiers by design (they are
# sent to browsers in OAuth redirects and shipped in client-side code); the credential that must
# stay secret is the OAuth client secret, detected by a separate template.
KNOWN_FP_MATCHERS: set[tuple[str, str | None]] = {
    ("form-detection", None),
    ("google-client-id", None),
    ("CVE-2026-111497", None),
    ("CVE-2022-44727", "lglaw-v1-sqli"),
    ("CVE-2022-44727", "lglaw-v2-sqli"),
    ("dns-waf-detect", "cloudflare"),
}

# The upstream self-signed-ssl template reports a certificate as self-signed whenever the
# `self_signed` handshake flag is true. On a bare-IP TLS handshake there is no hostname to use as
# SNI, so a server presents its default fallback certificate; large CDN/frontend IPs (Google's
# 74.125.0.0/16, etc.) answer with a self-signed certificate that is not the service's real,
# CA-issued one. Such a finding is an artifact of IP scanning, so it is suppressed agent-side for
# bare-IP targets only. Domain targets use the hostname as SNI and keep genuine self-signed
# certificates reported.
SELF_SIGNED_SSL_TEMPLATE_ID = "self-signed-ssl"

# Upstream cookie-attribute templates (missing-cookie-samesite-strict, cookies-without-secure,
# cookies-without-httponly) treat any Set-Cookie seen on a scanned host as an application session
# cookie. They also flag infrastructure cookies (Cloudflare/Google load-balancer bot cookies) and
# expired cookie-deletion directives, which are not application session cookies, so those findings
# are suppressed agent-side when the response carries no application cookie.
COOKIE_ATTRIBUTE_TEMPLATE_IDS = {
    "missing-cookie-samesite-strict",
    "cookies-without-secure",
    "cookies-without-httponly",
}

# The upstream s3-detect template fires on the generic AWS error-code regex
# `InvalidURI|InvalidArgument|NoSuchBucket` OR on S3-specific headers. Those error codes are also
# returned by other AWS services (CloudFront returns InvalidURI for a malformed path like `/%c0`),
# so a response that matches only the error-code regex and carries no S3 header marker is not an
# S3 bucket and is reported as one. Such a finding is a false positive and is suppressed.
S3_DETECT_TEMPLATE_ID = "s3-detect"

# The upstream weak-csp-detect template's `unsafe-script-src` and `unsafe-default-src` matchers
# fire on a CSP directive that contains `unsafe-inline`/`unsafe-eval`/`unsafe-hashes`, a bare
# any-origin `*`, `data:` or `blob:`. Their regex also matches a `*` inside a subdomain-scoped
# wildcard (e.g. `*.arkoselabs.com`), which does not let scripts load from any origin, so a policy
# whose only flagged sources are such subdomain wildcards is reported as weak without an unsafe
# keyword. Only those two matchers share the bug; the `missing-script-src`/`missing-object-src`
# matchers of the same template are left alone.
WEAK_CSP_DETECT_TEMPLATE_ID = "weak-csp-detect"
WEAK_CSP_UNSAFE_MATCHERS = {"unsafe-script-src", "unsafe-default-src"}

# Cookie names set by edge infrastructure rather than by the scanned application: Cloudflare bot
# management, Google Cloud Load Balancer affinity and anti-abuse cookies, AWS ELB/ALB sticky
# cookies and Akamai bot-manager cookies. A missing SameSite/Secure/HttpOnly attribute on them is
# not a weakness of the scanned application.
INFRASTRUCTURE_COOKIE_NAMES = {
    "__cf_bm",
    "__cfduid",
    "__cflb",
    "__cfruid",
    "_cfuvid",
    "cf_clearance",
    "gclb",
    "google_abuse_exemption",
    "awsalb",
    "awsalbtg",
    "awselb",
    "awselbcors",
    "ak_bmsc",
    "bm_sz",
    "_abck",
}


def _is_known_false_positive(nuclei_data_dict: dict[str, Any]) -> bool:
    """Tell whether a nuclei result matches a known false-positive template.

    Args:
        nuclei_data_dict: A single parsed nuclei JSON event.

    Returns:
        True when the (template-id, matcher-name) pair is a known false positive.
    """
    template_id = nuclei_data_dict.get("template-id")
    matcher_name = nuclei_data_dict.get("matcher-name")
    return (template_id, matcher_name) in KNOWN_FP_MATCHERS


def _extract_set_cookie_values(response: str) -> list[str]:
    """Extract the Set-Cookie header values of a raw HTTP response.

    Args:
        response: The raw HTTP response captured by nuclei.

    Returns:
        The values of the `Set-Cookie` headers, in order of appearance.
    """
    values = []
    for line in response.splitlines():
        if line == "":
            break
        if line.lower().startswith("set-cookie:"):
            values.append(line.split(":", 1)[1].strip())
    return values


def _is_deletion_directive(set_cookie: str) -> bool:
    """Tell whether a Set-Cookie value is an expired cookie-deletion directive.

    A non-positive Max-Age or an epoch Expires date drops the cookie. An empty
    value or the literal `deleted` does not, by itself, expire a cookie.
    Max-Age takes precedence over Expires, including when it keeps a cookie alive.

    Args:
        set_cookie: One `Set-Cookie` header value.

    Returns:
        True when the cookie is a deletion directive.
    """
    attributes = {}
    for attribute in set_cookie.split(";")[1:]:
        name, separator, value = attribute.partition("=")
        if separator == "=":
            name = name.strip().lower()
            value = value.strip()
            if name == "max-age" and re.fullmatch(r"-?[0-9]+", value) is None:
                continue
            attributes[name] = value
    max_age = attributes.get("max-age")
    if max_age is not None and re.fullmatch(r"-?[0-9]+", max_age) is not None:
        return max_age.startswith("-") or max_age.strip("0") == ""
    expires = attributes.get("expires")
    if expires is None:
        return False
    try:
        # Restrict this proof to explicit epoch expiry. Comparing an archived
        # response's cookies with today's time would suppress formerly live ones.
        return email.utils.parsedate_to_datetime(expires).year == 1970
    except (ValueError, TypeError, OverflowError):
        return False


def _is_infrastructure_cookie(set_cookie: str) -> bool:
    """Tell whether a Set-Cookie value belongs to edge infrastructure.

    Args:
        set_cookie: One `Set-Cookie` header value.

    Returns:
        True when the cookie name is a known infrastructure/bot-management cookie.
    """
    name = set_cookie.split("=", 1)[0].strip().lower()
    return name in INFRASTRUCTURE_COOKIE_NAMES


def _is_cookie_attribute_false_positive(nuclei_data_dict: dict[str, Any]) -> bool:
    """Tell whether a cookie-attribute finding only concerns infrastructure or
    expired cookies rather than application session cookies.

    The upstream cookie-attribute templates fire on any Set-Cookie lacking the attribute, so a
    response that only sets infrastructure cookies or expired cookie-deletion directives is
    reported as an application cookie gap. Such a finding is a false positive and is suppressed
    only when every Set-Cookie of the response is a deletion directive or an infrastructure
    cookie; any application cookie keeps the finding reported.

    Args:
        nuclei_data_dict: A single parsed nuclei JSON event.

    Returns:
        True when the finding is a known cookie-attribute false positive.
    """
    if nuclei_data_dict.get("template-id") not in COOKIE_ATTRIBUTE_TEMPLATE_IDS:
        return False
    response = nuclei_data_dict.get("response")
    if not isinstance(response, str) or response == "":
        return False
    set_cookies = _extract_set_cookie_values(response)
    if len(set_cookies) == 0:
        return False
    return all(
        _is_deletion_directive(set_cookie) or _is_infrastructure_cookie(set_cookie)
        for set_cookie in set_cookies
    )


def _extract_csp_sources(response: str, directive_name: str) -> list[str]:
    """Collect enforced CSP sources for the directive and its subdirectives.

    The upstream matcher looks for the directive name as a prefix, so the
    script-src matcher can also fire on script-src-elem or script-src-attr.
    """
    sources: list[str] = []
    for line in response.splitlines():
        if line == "":
            break
        header_name, separator, header_value = line.partition(":")
        if separator != ":" or header_name.strip().lower() != "content-security-policy":
            continue
        for directive in header_value.split(";"):
            parts = directive.split()
            if len(parts) == 0:
                continue
            name = parts[0].lower()
            if name == directive_name or name.startswith(f"{directive_name}-"):
                sources.extend(parts[1:])
    return sources


def _csp_directive_source_is_unsafe(source: str) -> bool:
    """Tell whether one CSP source is genuinely unsafe under the weak-csp-detect matchers.

    A wildcard host allows every hostname, even with a scheme or port
    restriction. Subdomain wildcards and port-only wildcards keep the hostname
    restricted.

    Args:
        source: One whitespace-separated CSP source.

    Returns:
        True when the source is genuinely unsafe, False otherwise.
    """
    source = source.strip().lower()
    _, _, authority = source.rpartition("://")
    host = authority.partition("/")[0].partition(":")[0]
    return host == "*" or source.startswith(("'unsafe-", "data:", "blob:"))


def _is_weak_csp_subdomain_wildcard_fp(nuclei_data_dict: dict[str, Any]) -> bool:
    """Tell whether a weak-csp-detect finding only flags subdomain-scoped wildcards.

    The `unsafe-script-src`/`unsafe-default-src` matchers report any directive that contains
    `unsafe-inline`/`unsafe-eval`/`unsafe-hashes`, host wildcards, `data:` or `blob:`.
    A directive whose only flagged sources are subdomain-scoped wildcards (e.g. `*.arkoselabs.com`)
    carries no such unsafe keyword, so the finding is a false positive. Any genuinely unsafe source
    keeps the finding reported.

    Args:
        nuclei_data_dict: A single parsed nuclei JSON event.

    Returns:
        True when the finding is a known weak-csp-detect subdomain-wildcard false positive.
    """
    if nuclei_data_dict.get("template-id") != WEAK_CSP_DETECT_TEMPLATE_ID:
        return False
    matcher_name = nuclei_data_dict.get("matcher-name")
    if matcher_name not in WEAK_CSP_UNSAFE_MATCHERS:
        return False
    directive_name = (
        "script-src" if matcher_name == "unsafe-script-src" else "default-src"
    )
    response = nuclei_data_dict.get("response")
    if not isinstance(response, str) or response == "":
        return False
    sources = _extract_csp_sources(response, directive_name)
    if len(sources) == 0:
        return False
    return not any(_csp_directive_source_is_unsafe(source) for source in sources)


def _is_bare_ip_target(matched_at: str) -> bool:
    """Tell whether the host of a matched target is a bare IP address.

    Args:
        matched_at: The `matched-at` value of a nuclei finding, e.g. `74.125.29.101:443`,
            `example.com:443` or `[2001:db8::1]:443`.

    Returns:
        True when the host is an IP address rather than a domain name.
    """
    target = matched_at.split("://", 1)[-1]
    if target.startswith("["):
        candidates = [target.split("]", 1)[0][1:]]
    else:
        # The whole target covers a bare address (e.g. `2001:db8::1`); the port-stripped part
        # covers an IPv4 or unbracketed IPv6 address followed by a port (e.g. `74.125.29.101:443`).
        candidates = [target, target.rsplit(":", 1)[0]]
    for candidate in candidates:
        try:
            ipaddress.ip_address(candidate)
            return True
        except ValueError:
            continue
    return False


def _is_self_signed_ssl_bare_ip_fp(nuclei_data_dict: dict[str, Any]) -> bool:
    """Tell whether a self-signed SSL finding is a bare-IP no-SNI fallback certificate.

    A bare-IP TLS handshake carries no hostname to use as SNI, so the server presents its default
    fallback certificate. Large CDN/frontend IPs answer such a handshake with a self-signed
    certificate, which makes the self-signed-ssl template report an artifact of IP scanning rather
    than the scanned service's real, CA-issued certificate. Such a certificate is not a signal
    about the scanned asset, so the finding is suppressed. Domain targets keep genuine self-signed
    certificates reported.

    Args:
        nuclei_data_dict: A single parsed nuclei JSON event.

    Returns:
        True when the finding is a self-signed SSL false positive on a bare-IP target.
    """
    if nuclei_data_dict.get("template-id") != SELF_SIGNED_SSL_TEMPLATE_ID:
        return False
    matched_at = nuclei_data_dict.get("matched-at")
    if not isinstance(matched_at, str) or matched_at == "":
        return False
    return _is_bare_ip_target(matched_at)


def _is_s3_detect_false_positive(nuclei_data_dict: dict[str, Any]) -> bool:
    """Tell whether an s3-detect finding matched a non-S3 AWS error page.

    The upstream s3-detect template's body regex matches `InvalidURI`, `InvalidArgument` and
    `NoSuchBucket`, generic AWS error codes that other services (e.g. CloudFront) also return. A
    response that only matches that regex and carries none of the S3 header markers
    (`Server: AmazonS3`, `x-amz-request-id`, `x-amz-id-2`) is not an S3 bucket, so the
    "Detect Amazon-S3 Bucket" finding is a false positive and is suppressed. A response with any
    S3 marker keeps the finding reported.

    Args:
        nuclei_data_dict: A single parsed nuclei JSON event.

    Returns:
        True when the finding is an s3-detect false positive on a non-S3 error page.
    """
    if nuclei_data_dict.get("template-id") != S3_DETECT_TEMPLATE_ID:
        return False
    response = nuclei_data_dict.get("response")
    if not isinstance(response, str) or response == "":
        return False
    header_block = response.split("\r\n\r\n", 1)[0].lower()
    # Mirror the template's own S3-confirming dsl matcher: an S3 response always carries one of
    # these markers. `x-amz-cf-id` (CloudFront) does not contain `x-amz-id`, so it is not matched.
    has_s3_marker = (
        "amazons3" in header_block
        or "x-amz-request-id" in header_block
        or "x-amz-id-2" in header_block
    )
    return not has_s3_marker


@dataclasses.dataclass
class Target:
    name: str
    schema: str | None = None
    port: int | None = None


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
        self._template_ids: list[str] | None = self.args.get("template_ids")
        self._template_urls: list[str] | None = self.args.get("template_urls")
        self._max_host_error = int(
            self.args.get("max_host_error", DEFAULT_MAX_HOST_ERROR)
        )
        self._request_timeout = int(
            self.args.get("timeout", DEFAULT_REQUEST_TIMEOUT_SECONDS)
        )
        self._request_retries = int(self.args.get("retries", DEFAULT_REQUEST_RETRIES))
        self._templates_dir: tempfile.TemporaryDirectory[str] | None = None
        self._templates_cache: dict[str, str] = {}
        self._templates_lock = threading.Lock()
        self._skip_unreachable_targets: bool = (
            self.args.get("skip_unreachable_targets", True) is True
        )

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

        self._mark_target_as_processed(message)
        logger.info("Preparing targets ...")
        targets = self.prepare_targets(message)
        # Filter out all the target that are out of scope.
        targets = [
            t
            for t in targets
            if self._should_process_target(self._scope_urls_regex, t) is True
        ]

        # Targets that don't answer burn the request budget on errors and retries, skip them upfront. The probe is
        # not made through a proxy, so it is only meaningful when nuclei is reaching the targets directly.
        if self._skip_unreachable_targets is True and self._proxy is None:
            reachable_targets = helpers.filter_reachable_targets(targets)
            skipped_targets = [t for t in targets if t not in reachable_targets]
            if len(skipped_targets) > 0:
                logger.warning("Skipping unreachable targets `%s`.", skipped_targets)
            targets = reachable_targets

        logger.info("Scanning targets `%s`.", targets)

        self._basic_credentials = build_basic_credential_from_message(
            message
        ) or build_basic_credential_from_args(self.args.get("basic_credentials"))
        if len(targets) > 0:
            if self._template_urls is not None:
                logger.debug("Running custom templates.")
                self._run_templates(targets)
            elif self._template_ids is not None:
                self._run_command(targets, run_default_templates=False)

            if self.args.get("use_default_templates", True):
                logger.debug("Running default templates.")
                self._run_command(targets, run_default_templates=True)
        logger.info("Done scanning targets.")

    def _parse_output(self) -> None:
        """Parse Nuclei Json output and emit the findings as vulnerabilities"""
        if path.exists(OUTPUT_PATH) is False:
            return
        with open(OUTPUT_PATH, "r", encoding="UTF-8") as f:
            lines = f.readlines()
            for line in lines:
                try:
                    nuclei_data_dict = json.loads(line)
                except json.decoder.JSONDecodeError as e:
                    logger.warning("Error while trying to decode line: %s: %s", line, e)
                    continue
                if _is_known_false_positive(nuclei_data_dict) is True:
                    logger.info(
                        "Skipping known false positive template `%s`.",
                        nuclei_data_dict.get("template-id"),
                    )
                    continue
                if _is_cookie_attribute_false_positive(nuclei_data_dict) is True:
                    logger.info(
                        "Skipping cookie attribute false positive template `%s`.",
                        nuclei_data_dict.get("template-id"),
                    )
                    continue
                if _is_weak_csp_subdomain_wildcard_fp(nuclei_data_dict) is True:
                    logger.info(
                        "Skipping weak-csp-detect subdomain wildcard false positive template `%s`.",
                        nuclei_data_dict.get("template-id"),
                    )
                    continue
                if _is_self_signed_ssl_bare_ip_fp(nuclei_data_dict) is True:
                    logger.info(
                        "Skipping self-signed SSL false positive on bare-IP target `%s`.",
                        nuclei_data_dict.get("matched-at"),
                    )
                    continue
                if _is_s3_detect_false_positive(nuclei_data_dict) is True:
                    logger.info(
                        "Skipping s3-detect false positive on non-S3 error page `%s`.",
                        nuclei_data_dict.get("matched-at"),
                    )
                    continue
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
                    technical_detail += f"""### {template_info.get("name")}: \n"""
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
                dna = helpers.compute_dna(
                    vulnerability_title=template_info.get("name"),
                    vuln_location=vuln_location,
                )
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
                    dna=dna,
                )

    def _get_references(
        self, template_info: dict[str, dict[str, list[str]]]
    ) -> dict[str, str]:
        """Generate dict references from nuclei references template"""
        references = {}
        cwe_list = template_info.get("classification", {}).get("cwe-id", [])
        if cwe_list is not None:
            for value in cwe_list:
                link = f"""https://nvd.nist.gov/vuln/detail/{value.replace("cwe-", "")}.html"""
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

    def _run_templates(self, targets: list[str]) -> None:
        """Run Nuclei scan on the provided templates"""
        templates = self._get_templates()
        if len(templates) > 0:
            self._run_command(targets, templates)

    def _get_templates(self) -> list[str]:
        """Return the local paths of the custom templates, downloading each of them only once.

        The templates are the same for every target, they are fetched in parallel the first time they are needed
        and reused for the following targets. A template that failed to download is retried a few times with a
        short backoff before the scan goes on without it, so a transient error does not silently drop a template
        for the current target, and it is tried again on the next target.
        """
        if self._template_urls is None or len(self._template_urls) == 0:
            raise ValueError("No template URLs provided")

        with self._templates_lock:
            if self._templates_dir is None:
                self._templates_dir = tempfile.TemporaryDirectory()
            templates_dir = pathlib.Path(self._templates_dir.name)
            missing_urls = [
                u for u in self._template_urls if u not in self._templates_cache
            ]
            for attempt in range(TEMPLATE_DOWNLOAD_RETRIES + 1):
                if len(missing_urls) == 0:
                    break
                if attempt > 0:
                    time.sleep(TEMPLATE_DOWNLOAD_BACKOFF_SECONDS * attempt)
                self._download_templates(missing_urls, templates_dir)
                missing_urls = [
                    u for u in missing_urls if u not in self._templates_cache
                ]
            if len(missing_urls) > 0:
                logger.warning(
                    "Running without %d of %d custom templates that failed to download.",
                    len(missing_urls),
                    len(self._template_urls),
                )
            return [
                self._templates_cache[u]
                for u in self._template_urls
                if u in self._templates_cache
            ]

    def _download_templates(self, urls: list[str], templates_dir: pathlib.Path) -> None:
        """Download the templates in parallel and cache the paths of the ones that succeeded."""
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=TEMPLATE_DOWNLOAD_WORKERS
        ) as executor:
            downloaded = executor.map(
                lambda u: self._download_template(u, templates_dir), urls
            )
            for url, template_path in zip(urls, downloaded):
                if template_path is not None:
                    self._templates_cache[url] = template_path

    def _download_template(self, url: str, templates_dir: pathlib.Path) -> str | None:
        """Download one template, returns its local path or None when the download failed."""
        try:
            response = requests.get(
                url, allow_redirects=True, timeout=TEMPLATE_DOWNLOAD_TIMEOUT_SECONDS
            )
        except requests.exceptions.RequestException as e:
            logger.warning("Failed to download template %s: %s", url, e)
            return None
        if response.status_code != 200:
            logger.warning(
                "Failed to download template %s: status %s", url, response.status_code
            )
            return None
        # The url hash keeps two templates that share a file name from overwriting each other.
        template_dir = templates_dir / hashlib.sha256(url.encode()).hexdigest()[:12]
        template_dir.mkdir(exist_ok=True)
        template_path = template_dir / url.split("/")[-1]
        template_path.write_bytes(response.content)
        return str(template_path)

    def _is_target_already_processed(self, message: m.Message) -> bool:
        """Checks if the target has already been processed before, relies on the redis server."""
        if (
            message.data.get("url") is not None
            or message.data.get("name") is not None
            or message.data.get("endpoint_url") is not None
        ):
            unicity_check_key = self._get_unique_check_key(message)
            if unicity_check_key is None:
                return True

            return self.set_is_member("agent_nuclei_asset", unicity_check_key)
        elif message.data.get("host") is not None:
            host = str(message.data.get("host"))
            mask = message.data.get("mask")
            port = self._get_port(message)
            if mask is not None:
                addresses = ipaddress.ip_network(f"{host}/{mask}", strict=False)
                return self.ip_network_exists(
                    "agent_nuclei_asset", addresses, lambda ip: f"{ip}_{port}"
                )
            else:
                return self.set_is_member("agent_nuclei_asset", f"{host}_{port}")
        else:
            logger.error("Unknown target %s", message)
            return True

    def _mark_target_as_processed(self, message: m.Message) -> None:
        """Mark the target as processed, relies on the redis server."""
        if (
            message.data.get("url") is not None
            or message.data.get("name") is not None
            or message.data.get("endpoint_url") is not None
        ):
            unicity_check_key = self._get_unique_check_key(message)
            if unicity_check_key is None:
                return

            self.set_add("agent_nuclei_asset", unicity_check_key)
        elif message.data.get("host") is not None:
            host = str(message.data.get("host"))
            mask = message.data.get("mask")
            port = self._get_port(message)
            if mask is not None:
                addresses = ipaddress.ip_network(f"{host}/{mask}", strict=False)
                self.add_ip_network(
                    "agent_nuclei_asset", addresses, lambda host: f"{host}_{port}"
                )
            else:
                self.set_add("agent_nuclei_asset", f"{host}_{port}")
        else:
            logger.error("Unknown target %s", message)
            return

    def _get_unique_check_key(self, message: m.Message) -> str | None:
        """Compute a unique key for a target"""
        if message.data.get("url") is not None:
            target = self._get_target_from_url(message)
            if target is not None:
                return f"{target.schema}_{target.name}_{target.port}"
        elif message.data.get("endpoint_url") is not None:
            target = self._get_target_from_url(message=message, field="endpoint_url")
            if target is not None:
                return f"{target.schema}_{target.name}_{target.port}"
        elif message.data.get("name") is not None:
            port = self._get_port(message)
            schema = self._get_schema(message)
            domain = message.data["name"]
            return f"{schema}_{domain}_{port}"
        return None

    def _get_target_from_url(
        self, message: m.Message, field: str = "url"
    ) -> Target | None:
        """Compute schema and port from a URL"""
        url = message.data[field]
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

    def prepare_targets(self, message: m.Message) -> list[str]:
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
            port = self._get_port(message)
            return [f"{h}:{port}" for h in ip_network.hosts()]

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
        elif (endpoint_url := message.data.get("endpoint_url")) is not None:
            return [endpoint_url]
        else:
            return []

    def _run_command(
        self,
        targets: list[str],
        templates: list[str] | None = None,
        run_default_templates: bool = False,
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
            command.extend(
                [
                    "-max-host-error",
                    str(self._max_host_error),
                    "-timeout",
                    str(self._request_timeout),
                    "-retries",
                    str(self._request_retries),
                ]
            )
            if run_default_templates is False:
                if templates is not None:
                    for template in templates:
                        if path.exists(template) is True:
                            command.extend(["-t", template])
                if self._template_ids is not None:
                    for template_id in self._template_ids:
                        command.extend(["-id", template_id])

            if len(self._basic_credentials) == 0:
                self._run_nuclei_command(command)
            else:
                for basic_credential in self._basic_credentials:
                    self._run_nuclei_command([*command, "-H", basic_credential.header])

    def _run_nuclei_command(self, command: list[str]) -> None:
        try:
            subprocess.run(
                command,
                capture_output=True,
                check=True,
                timeout=NUCLEI_TIMEOUT_SECONDS,
            )
            self._parse_output()
        except subprocess.CalledProcessError as e:
            logger.error("Error running nuclei %s", e)
        except subprocess.TimeoutExpired as e:
            logger.error("Error running nuclei timed out %s", e)
            self._parse_output()

    def _should_process_target(self, scope_urls_regex: str | None, url: str) -> bool:
        if scope_urls_regex is None:
            return True
        link_in_scan_domain = re.match(scope_urls_regex, url) is not None
        if not link_in_scan_domain:
            logger.warning("link url %s is not in domain %s", url, scope_urls_regex)
        return link_in_scan_domain


if __name__ == "__main__":
    logger.info("starting agent ...")
    AgentNuclei.main()
