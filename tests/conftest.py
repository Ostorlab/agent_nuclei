"""Pytest fixture for the nuclei agent."""
import pathlib
import random
import json

import pytest

from ostorlab.agent.message import message
from ostorlab.agent import definitions as agent_definitions
from ostorlab.runtimes import definitions as runtime_definitions
from ostorlab.utils import defintions as utils_definitions

from agent import agent

@pytest.fixture
def scan_message():
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
def scan_message_link():
    """Creates a dummy message of type v3.asset.ip.v4 to be used by the agent for testing purposes.
    """
    selector = 'v3.asset.link'
    msg_data = {
            'url': 'https://apple.com',
            'method': 'GET'
        }
    return message.Message.from_data(selector, data=msg_data)

@pytest.fixture
def nuclei_agent():
    with (pathlib.Path(__file__).parent.parent / 'ostorlab.yaml').open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        settings = runtime_definitions.AgentSettings(
            key='agent/ostorlab/nuclei',
            bus_url='NA',
            bus_exchange_topic='NA',
            args=[],
            healthcheck_port=random.randint(5000, 6000),
            redis_url='redis://guest:guest@localhost:6379')

        agent_object = agent.AgentNuclei(definition, settings)
        return agent_object


@pytest.fixture
def nuclei_agent_args():
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
                      'https://raw.githubusercontent.com/Ostorlab/main/templates/CVE2.yaml']).encode())],
            healthcheck_port=random.randint(5000, 6000),
            redis_url='redis://guest:guest@localhost:6379')

        agent_object = agent.AgentNuclei(definition, settings)
        return agent_object
