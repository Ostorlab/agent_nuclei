"""Pytest fixture for the nuclei agent_nuclei."""
import pathlib
import random
import json

import pytest

from ostorlab.agent.message import message
from ostorlab.agent import definitions as agent_definitions
from ostorlab.runtimes import definitions as runtime_definitions
from ostorlab.utils import defintions as utils_definitions

from agent import agent_nuclei


@pytest.fixture
def scan_message() -> message.Message:
    """Creates a dummy message of type v3.asset.ip.v4 to be used by the agent for testing purposes.
    """
    selector = 'v3.asset.ip.v4'
    msg_data = {
        'host': '209.235.136.112',
        'mask': '32',
        'version': 4
    }
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def scan_message_network_range() -> message.Message:
    """Creates a dummy message of type v3.asset.ip.v4 to be used by the agent for testing purposes.
    """
    selector = 'v3.asset.ip.v4'
    msg_data = {
        'host': '209.235.136.112',
        'mask': '28',
        'version': 4
    }
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def scan_message_large_network_range() -> message.Message:
    """Creates a dummy message of type v3.asset.ip.v4 to be used by the agent for testing purposes.
    """
    selector = 'v3.asset.ip.v4'
    msg_data = {
        'host': '209.235.136.112',
        'mask': '16',
        'version': 4
    }
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def scan_message_link() -> message.Message:
    """Creates a dummy message of type v3.asset.link to be used by the agent for testing purposes.
    """
    selector = 'v3.asset.link'
    msg_data = {
        'url': 'https://apple.com',
        'method': 'GET'
    }
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def scan_message_link_2() -> message.Message:
    """Creates a dummy message of type v3.asset.link to be used by the agent for testing purposes.
    """
    selector = 'v3.asset.link'
    msg_data = {
        'url': 'https://ostorlab.co',
        'method': 'GET'
    }
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def scan_message_domain() -> message.Message:
    """Creates a dummy message of type v3.asset.domain_name to be used by the agent for testing purposes.
    """
    selector = 'v3.asset.domain_name'
    msg_data = {
        'name': 'apple.com'
    }
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def scan_message_domain_2() -> message.Message:
    """Creates a dummy message of type v3.asset.domain_name to be used by the agent for testing purposes.
    """
    selector = 'v3.asset.domain_name'
    msg_data = {
        'name': 'ostorlab.co'
    }
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def nuclei_agent() -> agent_nuclei.AgentNuclei:
    with (pathlib.Path(__file__).parent.parent / 'ostorlab.yaml').open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        definition.args[4]['value'] = '([a-zA-Z]+://apple.com/?.*)'
        settings = runtime_definitions.AgentSettings(
            key='agent/ostorlab/nuclei',
            bus_url='NA',
            bus_exchange_topic='NA',
            args=[],
            healthcheck_port=random.randint(5000, 6000),
            redis_url='redis://guest:guest@localhost:6379')

        agent_object = agent_nuclei.AgentNuclei(definition, settings)
        return agent_object


@pytest.fixture
def nuclei_agent_no_url_scope() -> agent_nuclei.AgentNuclei:
    with (pathlib.Path(__file__).parent.parent / 'ostorlab.yaml').open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        settings = runtime_definitions.AgentSettings(
            key='agent/ostorlab/nuclei',
            bus_url='NA',
            bus_exchange_topic='NA',
            args=[],
            healthcheck_port=random.randint(5000, 6000),
            redis_url='redis://guest:guest@localhost:6379')

        agent_object = agent_nuclei.AgentNuclei(definition, settings)
        return agent_object


@pytest.fixture
def nuclei_agent_args() -> agent_nuclei.AgentNuclei:
    with (pathlib.Path(__file__).parent.parent / 'ostorlab.yaml').open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        settings = runtime_definitions.AgentSettings(
            key='agent/ostorlab/nuclei',
            bus_url='NA',
            bus_exchange_topic='NA',
            args=[
                utils_definitions.Arg(
                    name='template_urls',
                    type='array',
                    value=json.dumps(['https://raw.githubusercontent.com/Ostorlab/main/templates/CVE1.yaml',
                                      'https://raw.githubusercontent.com/Ostorlab/main/templates/CVE2.yaml'])
                    .encode())],
            healthcheck_port=random.randint(5000, 6000),
            redis_url='redis://guest:guest@localhost:6379')

        agent_object = agent_nuclei.AgentNuclei(definition, settings)
        return agent_object


@pytest.fixture
def ip_small_range_message() -> message.Message:
    """Creates a dummy message of type v3.asset.ip.v4 with a small mask to be used by the agent for testing purposes."""
    selector = 'v3.asset.ip.v4'
    msg_data = {
        'host': '42.42.42.42',
        'mask': '31',
        'version': 4
    }
    return message.Message.from_data(selector, data=msg_data)
