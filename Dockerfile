FROM ubuntu:latest as base

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y software-properties-common  \
    && add-apt-repository ppa:deadsnakes/ppa \
    && apt-get remove -y python*

RUN apt-get -y install python3.11 python3.11-dev python3-pip wget zip wireguard iproute2 openresolv  \
    && python3.11 -m pip install --upgrade pip

COPY requirement.txt /requirement.txt
RUN python3.11 -m pip install -r /requirement.txt
RUN mkdir /nuclei
WORKDIR /nuclei
ARG NUCLEI_VERSION=3.1.3
RUN wget https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip && \
  unzip nuclei_${NUCLEI_VERSION}_linux_amd64.zip
RUN mkdir -p /app/agent
ENV PYTHONPATH=/app
COPY agent /app/agent
COPY ostorlab.yaml /app/agent/ostorlab.yaml
WORKDIR /app
CMD ["python3.11", "/app/agent/agent_nuclei.py"]
