FROM python:3.8-alpine as builder

RUN apk update && \
    apk add --no-cache \
    curl \
    linux-headers \
    tcpdump \
    build-base \
    ebtables \
    make \
    git \
    bash && \
    curl -LO "https://storage.googleapis.com/kubernetes-release/release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/linux/amd64/kubectl" && \
    chmod +x ./kubectl && \
    mv ./kubectl /usr/local/bin/kubectl && \
    apk upgrade --no-cache

WORKDIR /kube-hunter
COPY . .
RUN make deps
RUN pip install .
RUN pip install kubernetes

FROM python:3.8-alpine

RUN apk add --no-cache \
    tcpdump \
    ebtables && \
    apk upgrade --no-cache

COPY --from=builder /usr/local/lib/python3.8/site-packages /usr/local/lib/python3.8/site-packages
COPY --from=builder /usr/local/bin/kube-hunter /usr/local/bin/kube-hunter
COPY --from=builder /kube-hunter/kube_hunter /kube_hunter
# COPY your script into the Docker image
COPY --from=builder /kube-hunter/kube_hunter/modules/hunting/rbac.py /kube_hunter/modules/hunting/rbac.py

# Add default plugins: https://github.com/aquasecurity/kube-hunter-plugins 
RUN pip install kube-hunter-arp-spoof>=0.0.3 kube-hunter-dns-spoof>=0.0.3

# Add kube_hunter package to PYTHONPATH
ENV PYTHONPATH="${PYTHONPATH}:/kube_hunter/kube_hunter/"

CMD ["python", "/kube_hunter/modules/hunting/rbac.py"]
