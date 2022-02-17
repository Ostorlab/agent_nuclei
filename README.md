
# Nuclei agent  
An implementation of [Osorlab Agent]((https://pypi.org/project/ostorlab/) for the [Nuclei scanner](https://github.com/projectdiscovery/nuclei) by ProjectDiscovery.  

## Usage

Refer to Ostorlab documentation.

### Build directly from the repository

 1. To build the nuclei agent you need to have [ostorlab](https://pypi.org/project/ostorlab/) installed in your machine.  if you have already installed ostorlab you can skip this step.
 
`pip3 install -U ostorlab` 
 
 3. clone this repository.
 
`git clone https://github.com/Ostorlab/agent_nuclei && cd agent_nuclei `
   
 4. build the agent image using ostorlab cli.

 `ostortlab agent build --file=ostorlab.yaml`

 ### Install directly from ostorlab agent store.
 
Run the command:

`ostorlab agent install agent/ostorlab/nuclei`
