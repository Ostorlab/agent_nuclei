FROM ubuntu:latest as base
RUN apt-get update && apt-get -y install python3.10 pip wget zip wireguard iproute2 openresolv
COPY requirement.txt /requirement.txt
RUN pip install -r /requirement.txt
RUN mkdir /nuclei
WORKDIR /nuclei
ARG NUCLEI_VERSION=2.7.7
RUN wget https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip && \
  unzip nuclei_${NUCLEI_VERSION}_linux_amd64.zip
RUN mkdir -p /app/agent
ENV PYTHONPATH=/app
COPY agent /app/agent
COPY ostorlab.yaml /app/agent/ostorlab.yaml
WORKDIR /app
CMD ["python3", "/app/agent/agent_nuclei.py"]
