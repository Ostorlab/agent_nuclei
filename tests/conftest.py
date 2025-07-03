"""Pytest fixture for the nuclei agent_nuclei."""

import pathlib
import random
import json

import pytest

from ostorlab.agent.message import message
from ostorlab.agent import definitions as agent_definitions
from ostorlab.runtimes import definitions as runtime_definitions
from ostorlab.utils import definitions as utils_definitions

from agent import agent_nuclei


@pytest.fixture
def scan_message() -> message.Message:
    """Creates a dummy message of type v3.asset.ip.v4 to be used by the agent for testing purposes."""
    selector = "v3.asset.ip.v4"
    msg_data = {"host": "209.235.136.112", "mask": "32", "version": 4}
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def scan_message_network_range() -> message.Message:
    """Creates a dummy message of type v3.asset.ip.v4 to be used by the agent for testing purposes."""
    selector = "v3.asset.ip.v4"
    msg_data = {"host": "209.235.136.112", "mask": "28", "version": 4}
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def scan_message_large_network_range() -> message.Message:
    """Creates a dummy message of type v3.asset.ip.v4 to be used by the agent for testing purposes."""
    selector = "v3.asset.ip.v4"
    msg_data = {"host": "209.235.136.112", "mask": "16", "version": 4}
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def scan_message_link() -> message.Message:
    """Creates a dummy message of type v3.asset.link to be used by the agent for testing purposes."""
    selector = "v3.asset.link"
    msg_data = {"url": "https://apple.com", "method": "GET"}
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def scan_message_link_2() -> message.Message:
    """Creates a dummy message of type v3.asset.link to be used by the agent for testing purposes."""
    selector = "v3.asset.link"
    msg_data = {"url": "https://ostorlab.co", "method": "GET"}
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def scan_message_domain() -> message.Message:
    """Creates a dummy message of type v3.asset.domain_name to be used by the agent for testing purposes."""
    selector = "v3.asset.domain_name"
    msg_data = {"name": "apple.com"}
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def scan_message_domain_2() -> message.Message:
    """Creates a dummy message of type v3.asset.domain_name to be used by the agent for testing purposes."""
    selector = "v3.asset.domain_name"
    msg_data = {"name": "ostorlab.co"}
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def scan_message_domain_query() -> message.Message:
    """Creates a dummy message of type v3.asset.domain_name to be used by the agent for testing purposes."""
    selector = "v3.asset.domain_name"
    msg_data = {"name": "apple.com?query=1"}
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def nuclei_agent(
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
) -> agent_nuclei.AgentNuclei:
    with (pathlib.Path(__file__).parent.parent / "ostorlab.yaml").open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        definition.args[4]["value"] = "([a-zA-Z]+://apple.com/?.*)"
        settings = runtime_definitions.AgentSettings(
            key="agent/ostorlab/nuclei",
            bus_url="NA",
            bus_exchange_topic="NA",
            args=[],
            healthcheck_port=random.randint(5000, 6000),
            redis_url="redis://guest:guest@localhost:6379",
        )

        agent_object = agent_nuclei.AgentNuclei(definition, settings)
        return agent_object


@pytest.fixture
def nuclei_agent_no_url_scope(
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
) -> agent_nuclei.AgentNuclei:
    with (pathlib.Path(__file__).parent.parent / "ostorlab.yaml").open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        settings = runtime_definitions.AgentSettings(
            key="agent/ostorlab/nuclei",
            bus_url="NA",
            bus_exchange_topic="NA",
            args=[],
            healthcheck_port=random.randint(5000, 6000),
            redis_url="redis://guest:guest@localhost:6379",
        )

        agent_object = agent_nuclei.AgentNuclei(definition, settings)
        return agent_object


@pytest.fixture
def nuclei_agent_args(
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
) -> agent_nuclei.AgentNuclei:
    with (pathlib.Path(__file__).parent.parent / "ostorlab.yaml").open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        settings = runtime_definitions.AgentSettings(
            key="agent/ostorlab/nuclei",
            bus_url="NA",
            bus_exchange_topic="NA",
            args=[
                utils_definitions.Arg(
                    name="template_urls",
                    type="array",
                    value=json.dumps(
                        [
                            "https://raw.githubusercontent.com/Ostorlab/main/templates/CVE1.yaml",
                            "https://raw.githubusercontent.com/Ostorlab/main/templates/CVE2.yaml",
                        ]
                    ).encode(),
                )
            ],
            healthcheck_port=random.randint(5000, 6000),
            redis_url="redis://guest:guest@localhost:6379",
        )

        agent_object = agent_nuclei.AgentNuclei(definition, settings)
        return agent_object


@pytest.fixture
def ip_small_range_message() -> message.Message:
    """Creates a dummy message of type v3.asset.ip.v4 with a small mask to be used by the agent for testing purposes."""
    selector = "v3.asset.ip.v4"
    msg_data = {"host": "42.42.42.42", "mask": "31", "version": 4}
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def scan_message_link_with_basic_credential() -> message.Message:
    """Creates a dummy message of type v3.asset.link with basic_credential to be used by the agent for testing
    purposes."""
    selector = "v3.asset.link"
    msg_data = {
        "url": "https://example.com",
        "method": "GET",
        "basic_credential": {"login": "username", "password": "dummy_value"},
    }
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def nuclei_agent_with_basic_credentials(
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
) -> agent_nuclei.AgentNuclei:
    with (pathlib.Path(__file__).parent.parent / "ostorlab.yaml").open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        settings = runtime_definitions.AgentSettings(
            key="agent/ostorlab/nuclei",
            bus_url="NA",
            bus_exchange_topic="NA",
            args=[
                utils_definitions.Arg(
                    name="basic_credentials",
                    type="array",
                    value=json.dumps(
                        [
                            {
                                "login": "username",
                                "password": "dummy_value",
                            },
                        ]
                    ).encode(),
                )
            ],
            healthcheck_port=random.randint(5000, 6000),
            redis_url="redis://guest:guest@localhost:6379",
        )

        agent_object = agent_nuclei.AgentNuclei(definition, settings)
        return agent_object


@pytest.fixture
def nuclei_agent_with_proxy(
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
) -> agent_nuclei.AgentNuclei:
    del agent_mock
    del agent_persist_mock
    with (pathlib.Path(__file__).parent.parent / "ostorlab.yaml").open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        settings = runtime_definitions.AgentSettings(
            key="agent/ostorlab/nuclei",
            bus_url="NA",
            bus_exchange_topic="NA",
            args=[
                utils_definitions.Arg(
                    name="proxy",
                    type="string",
                    value=json.dumps("https://proxy.co").encode(),
                )
            ],
            healthcheck_port=random.randint(5000, 6000),
            redis_url="redis://guest:guest@localhost:6379",
        )

        agent_object = agent_nuclei.AgentNuclei(definition, settings)
        return agent_object


@pytest.fixture
def nuclei_agent_with_template_ids(
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
) -> agent_nuclei.AgentNuclei:
    with (pathlib.Path(__file__).parent.parent / "ostorlab.yaml").open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        settings = runtime_definitions.AgentSettings(
            key="agent/ostorlab/nuclei",
            bus_url="NA",
            bus_exchange_topic="NA",
            args=[
                utils_definitions.Arg(
                    name="template_ids",
                    type="array",
                    value=json.dumps(
                        [
                            "cve-2021-1234",
                            "cve-2021-5678",
                        ]
                    ).encode(),
                )
            ],
            healthcheck_port=random.randint(5000, 6000),
            redis_url="redis://guest:guest@localhost:6379",
        )

        agent_object = agent_nuclei.AgentNuclei(definition, settings)
        return agent_object


@pytest.fixture
def nuclei_agent_with_custom_templates(
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
) -> agent_nuclei.AgentNuclei:
    with (pathlib.Path(__file__).parent.parent / "ostorlab.yaml").open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        definition.args = [
            {
                "name": "template_urls",
                "value": ["https://template1.yaml", "https://template2.yaml"],
            },
            {
                "name": "port",
                "value": 443,
            },
        ]
        settings = runtime_definitions.AgentSettings(
            key="agent/ostorlab/nuclei",
            bus_url="NA",
            bus_exchange_topic="NA",
            args=[],
            healthcheck_port=random.randint(5000, 6000),
            redis_url="redis://guest:guest@localhost:6379",
        )

        agent_object = agent_nuclei.AgentNuclei(definition, settings)
        return agent_object


@pytest.fixture()
def scan_message_ipv4_with_mask8() -> message.Message:
    """Creates a message of type v3.asset.ip.v4 to be used by the agent for testing purposes."""
    selector = "v3.asset.ip.v4"
    msg_data = {"host": "192.168.1.17", "mask": "8", "version": 4}
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture()
def scan_message_ipv6_with_mask64() -> message.Message:
    """Creates a message of type v3.asset.ip.v6 to be used by the agent for testing purposes."""
    selector = "v3.asset.ip.v6"
    msg_data = {
        "host": "2001:db8:3333:4444:5555:6666:7777:8888",
        "mask": "64",
        "version": 6,
    }
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture()
def scan_message_ipv6_with_mask112() -> message.Message:
    """Creates a message of type v3.asset.ip.v6 to be used by the agent for testing purposes."""
    selector = "v3.asset.ip.v6"
    msg_data = {
        "host": "2001:db8:3333:4444:5555:6666:7777:8888",
        "mask": "112",
        "version": 6,
    }
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture()
def scan_message_ipv4_with_port() -> message.Message:
    """Creates a message of type v3.asset.ip.v4 to be used by the agent for testing purposes."""
    selector = "v3.asset.ip.v4.port.service"
    msg_data = {
        "host": "192.168.0.1",
        "port": 8080,
        "service": "https",
        "version": 4,
        "mask": "32",
    }
    return message.Message.from_data(selector, data=msg_data)
