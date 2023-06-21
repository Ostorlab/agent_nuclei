FROM python:3.10-alpine as base
FROM base as builder

RUN mkdir /install
RUN apk add build-base
WORKDIR /install
COPY requirement.txt /requirement.txt
RUN pip install --prefix=/install -r /requirement.txt
FROM base
COPY --from=builder /install /usr/local
RUN mkdir /nuclei
WORKDIR /nuclei
ARG NUCLEI_VERSION=2.9.6
RUN wget https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip && \
  unzip nuclei_${NUCLEI_VERSION}_linux_amd64.zip
RUN mkdir -p /app/agent
ENV PYTHONPATH=/app
COPY agent /app/agent
COPY ostorlab.yaml /app/agent/ostorlab.yaml
WORKDIR /app
CMD ["python3", "/app/agent/agent_nuclei.py"]
