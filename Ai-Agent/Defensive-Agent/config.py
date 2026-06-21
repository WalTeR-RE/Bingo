"""WAF Monitor configuration."""

from dataclasses import dataclass

@dataclass
class WAFConfig:
    """
    Configuration for the WAF network monitor.

    Attributes:
        model_path:       Path to the trained waf_model.pkl file.
        threat_threshold: Minimum confidence (0-1) to flag as threat.
        proxy_host:       Bind address for the proxy server.
        proxy_port:       HTTP  proxy listening port.
        proxy_ssl_port:   HTTPS proxy listening port.
        upstream_host:    Backend server address to forward clean traffic to.
        upstream_port:    Backend server port.
        upstream_ssl:     Whether to use HTTPS when connecting to upstream.
        ssl_certfile:     PEM certificate for HTTPS interception (proxy mode).
        ssl_keyfile:      PEM private key  for HTTPS interception (proxy mode).
        interface:        Network interface for sniffer mode (empty = default).
        loopback:         Capture localhost / 127.0.0.1 traffic via the Npcap
                          loopback adapter (sniffer mode). Needs Npcap installed
                          with "Support loopback traffic" enabled.
        sniff_filter:     BPF filter for packet capture.
        block_threats:    True = return 403; False = log only and forward.
        log_file:         Path to log file (empty = console only).
        verbose:          Enable debug-level logging.
    """

    model_path: str = "waf_model.pkl"
    threat_threshold: float = 0.70

    proxy_host: str = "0.0.0.0"
    proxy_port: int = 8080
    proxy_ssl_port: int = 8443
    upstream_host: str = "127.0.0.1"
    upstream_port: int = 80
    upstream_ssl: bool = False

    ssl_certfile: str = ""
    ssl_keyfile: str = ""

    interface: str = ""
    loopback: bool = False
    sniff_filter: str = "tcp port 80 or tcp port 443 or tcp port 8080 or tcp port 8443 or tcp port 4280"

    block_threats: bool = True
    log_file: str = ""
    verbose: bool = False
