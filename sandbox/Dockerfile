# ReconSandbox — Cloudflare Sandbox base image + security recon tools
#
# This MUST track the @cloudflare/sandbox npm version in package.json — the
# container image is the server side of the sandbox control protocol, and a
# version mismatch with the client SDK breaks the control-port handshake
# ("The requested endpoint was not found" from RuntimeBootstrapProbe).
FROM docker.io/cloudflare/sandbox:0.13.0-next.751.1

# Security recon tools (nmap, curl, dig)
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    nmap \
    dnsutils \
    ca-certificates \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install subfinder (Go binary)
RUN wget -qO /tmp/subfinder.zip \
    https://github.com/projectdiscovery/subfinder/releases/download/v2.6.3/subfinder_2.6.3_linux_amd64.zip \
    && unzip -o /tmp/subfinder.zip -d /usr/local/bin \
    && chmod +x /usr/local/bin/subfinder \
    && rm -f /tmp/subfinder.zip

# Required for local dev port exposure (sandbox server)
EXPOSE 8080
