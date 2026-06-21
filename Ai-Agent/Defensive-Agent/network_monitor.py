"""
WAF Network Monitor — real-time web traffic analysis with on/off control.

Two operating modes
-------------------
* **proxy** (recommended) — reverse proxy that terminates HTTP *and* HTTPS,
  inspects every request through the WAF engine, and either blocks (403) or
  forwards to the upstream server.  HTTPS requires a TLS cert/key pair.
* **sniffer** — passive packet capture with *scapy*.  HTTP traffic is fully
  inspected; HTTPS traffic is encrypted so only connection metadata (SNI
  hostname, IPs, ports) is visible.  Use proxy mode for full HTTPS coverage.
  Set ``loopback=True`` on the config to capture ``localhost`` / ``127.0.0.1``
  traffic (e.g. a local DVWA on :4280) via the Npcap loopback adapter.

Quick start
-----------
    from final_result import WAFMonitor, WAFConfig

    monitor = WAFMonitor(WAFConfig(model_path="waf_model.pkl"))
    monitor.start()          # ON  — default proxy mode
    # ... application runs ...
    monitor.stop()           # OFF
"""

import http.client
import http.server
import json
import logging
import re
import socketserver
import ssl
import threading
import time
import urllib.parse
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional

from .config import WAFConfig
from .waf_engine import WAFEngine

logger = logging.getLogger("waf")

@dataclass
class ThreatEvent:
    """A single threat detected by the monitor."""
    timestamp: str
    source_ip: str
    source_port: int
    method: str
    url: str
    matched_payload: str
    prediction: str
    confidence: float
    action: str

    def to_dict(self) -> dict:
        return asdict(self)

@dataclass
class MonitorStats:
    """Cumulative monitoring statistics."""
    total_requests: int = 0
    safe_requests: int = 0
    threats_detected: int = 0
    threats_blocked: int = 0
    https_encrypted: int = 0
    start_time: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

class _WAFProxyHandler(http.server.BaseHTTPRequestHandler):
    """Inspect every HTTP(S) request through the WAF before forwarding."""

    waf_engine: WAFEngine = None
    config: WAFConfig = None
    stats: MonitorStats = None
    threat_log: list = None
    on_threat: Optional[Callable] = None
    _lock: threading.Lock = None

    def log_message(self, fmt, *args):
        if self.config and self.config.verbose:
            logger.debug(f"{self.client_address[0]} - {fmt % args}")

    @staticmethod
    def _decode_variants(raw: str) -> list[str]:
        """Return [raw, url-decoded, double-decoded] (duplicates removed)."""
        seen, out = set(), []
        for s in (raw, urllib.parse.unquote(raw)):
            if s not in seen:
                seen.add(s)
                out.append(s)
        double = urllib.parse.unquote(out[-1])
        if double not in seen:
            out.append(double)
        return out

    def _check_payload(self, payload: str) -> list[dict]:
        """Run WAF on payload + decoded variants, return threat results."""
        threats = []
        for variant in self._decode_variants(payload):
            result = self.waf_engine.analyze(variant)
            if result["is_threat"] and result["confidence"] >= self.config.threat_threshold:
                threats.append(result)
                break
        return threats

    def _analyze_request(self) -> list[dict]:
        """Classify the full request (method + URI + body) through the WAF model."""
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 0:
            self._request_body = self.rfile.read(content_length)
        else:
            self._request_body = b""
        body_text = self._request_body.decode("utf-8", errors="replace")
        request_text = f"{self.command} {self.path} {body_text}".strip()
        return self._check_payload(request_text)

    def _record_threats(self, threats: list[dict]):
        if not threats:
            return
        action = "blocked" if self.config.block_threats else "logged"
        t = max(threats, key=lambda x: x["confidence"])
        event = ThreatEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            source_ip=self.client_address[0],
            source_port=self.client_address[1],
            method=self.command,
            url=self.path,
            matched_payload=t["payload"][:200],
            prediction=t["prediction"],
            confidence=t["confidence"],
            action=action,
        )
        with self._lock:
            self.threat_log.append(event)
            self.stats.threats_detected += 1
            if action == "blocked":
                self.stats.threats_blocked += 1

        logger.warning(
            "THREAT [%s] %.0f%% from %s | %s %s | %s",
            event.prediction, event.confidence * 100,
            event.source_ip, event.method, event.url, event.action,
        )
        if self.on_threat:
            try:
                self.on_threat(event)
            except Exception:
                pass

    def _forward_to_upstream(self):
        try:
            ConnClass = (
                http.client.HTTPSConnection
                if self.config.upstream_ssl
                else http.client.HTTPConnection
            )
            conn = ConnClass(
                self.config.upstream_host,
                self.config.upstream_port,
                timeout=30,
            )

            hop = {
                "connection", "keep-alive", "proxy-authenticate",
                "proxy-authorization", "te", "trailers",
                "transfer-encoding", "upgrade",
            }
            fwd_headers = {
                k: v for k, v in self.headers.items()
                if k.lower() not in hop
            }
            xff = fwd_headers.get("X-Forwarded-For", "")
            client_ip = self.client_address[0]
            fwd_headers["X-Forwarded-For"] = (
                f"{xff}, {client_ip}" if xff else client_ip
            )

            conn.request(
                self.command, self.path,
                body=self._request_body,
                headers=fwd_headers,
            )
            resp = conn.getresponse()

            self.send_response(resp.status)
            for key, val in resp.getheaders():
                if key.lower() not in hop:
                    self.send_header(key, val)
            self.end_headers()

            while True:
                chunk = resp.read(8192)
                if not chunk:
                    break
                self.wfile.write(chunk)

            conn.close()
        except Exception as exc:
            logger.error("Upstream error: %s", exc)
            self.send_error(502, "Bad Gateway: upstream server error")

    def _handle_request(self):
        with self._lock:
            self.stats.total_requests += 1

        threats = self._analyze_request()

        if threats:
            self._record_threats(threats)
            if self.config.block_threats:
                self.send_response(403)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                body = json.dumps({
                    "blocked": True,
                    "reason": "WAF: malicious payload detected",
                    "threats": [
                        {
                            "type": t["prediction"],
                            "confidence": f"{t['confidence']:.2%}",
                        }
                        for t in threats
                    ],
                }, indent=2)
                self.wfile.write(body.encode())
                return

        with self._lock:
            self.stats.safe_requests += 1

        logger.info(
            "SAFE  %s %s from %s | total=%d threats=%d",
            self.command, self.path, self.client_address[0],
            self.stats.total_requests, self.stats.threats_detected,
        )

        self._forward_to_upstream()

    def do_GET(self):     self._handle_request()
    def do_POST(self):    self._handle_request()
    def do_PUT(self):     self._handle_request()
    def do_DELETE(self):  self._handle_request()
    def do_PATCH(self):   self._handle_request()
    def do_HEAD(self):    self._handle_request()
    def do_OPTIONS(self): self._handle_request()

class _ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

class WAFMonitor:
    """
    WAF network monitor with **on / off** switch.

    Parameters
    ----------
    config : WAFConfig
        All tunables (paths, ports, thresholds …).
    on_threat : callable, optional
        ``fn(ThreatEvent)`` invoked on every detected threat.

    Examples
    --------
    >>> monitor = WAFMonitor(WAFConfig(model_path="waf_model.pkl"))
    >>> monitor.start()          # ON  (default = proxy mode)
    >>> monitor.is_running
    True
    >>> monitor.stop()           # OFF
    """

    def __init__(
        self,
        config: WAFConfig | None = None,
        on_threat: Callable | None = None,
    ):
        self.config = config or WAFConfig()
        self._engine = WAFEngine(self.config.model_path)
        self._on_threat = on_threat
        self._running = threading.Event()
        self._lock = threading.Lock()
        self._threads: list[threading.Thread] = []
        self._servers: list = []
        self._stats = MonitorStats()
        self._threat_log: list[ThreatEvent] = []

        self._setup_logging()

    @property
    def is_running(self) -> bool:
        """``True`` while monitoring is active."""
        return self._running.is_set()

    @property
    def stats(self) -> dict:
        """Current monitoring statistics as a plain dict."""
        return self._stats.to_dict()

    @property
    def threat_log(self) -> list[dict]:
        """List of all detected threats (dicts)."""
        with self._lock:
            return [t.to_dict() for t in self._threat_log]

    @property
    def engine(self) -> WAFEngine:
        """Direct access to the underlying WAFEngine (for ad-hoc queries)."""
        return self._engine

    def start(self, mode: str = "proxy") -> None:
        """
        **Turn ON** the WAF monitor.

        Parameters
        ----------
        mode : ``"proxy"`` | ``"sniffer"``
            *proxy*  — reverse proxy, full HTTP + HTTPS inspection.
            *sniffer* — passive packet capture (HTTP only; HTTPS metadata).
        """
        if self._running.is_set():
            logger.warning("Monitor is already running")
            return

        self._running.set()
        self._stats = MonitorStats(
            start_time=datetime.now(timezone.utc).isoformat(),
        )

        if mode == "proxy":
            self._start_proxy()
        elif mode == "sniffer":
            self._start_sniffer()
        else:
            self._running.clear()
            raise ValueError(f"Unknown mode '{mode}'. Use 'proxy' or 'sniffer'.")

        logger.info("WAF Monitor  ON  (%s mode)", mode)

    def stop(self) -> None:
        """**Turn OFF** the WAF monitor and clean up."""
        if not self._running.is_set():
            return

        self._running.clear()

        for server in self._servers:
            try:
                server.shutdown()
            except Exception:
                pass

        for thread in self._threads:
            thread.join(timeout=5)

        self._servers.clear()
        self._threads.clear()
        logger.info("WAF Monitor  OFF")

    def _start_proxy(self):
        _WAFProxyHandler.waf_engine = self._engine
        _WAFProxyHandler.config = self.config
        _WAFProxyHandler.stats = self._stats
        _WAFProxyHandler.threat_log = self._threat_log
        _WAFProxyHandler.on_threat = self._on_threat
        _WAFProxyHandler._lock = self._lock

        http_srv = _ThreadingHTTPServer(
            (self.config.proxy_host, self.config.proxy_port),
            _WAFProxyHandler,
        )
        t = threading.Thread(target=http_srv.serve_forever, daemon=True)
        t.start()
        self._servers.append(http_srv)
        self._threads.append(t)
        logger.info(
            "═══════════════════════════════════════════════════"
        )
        logger.info(
            "  WAF Proxy LISTENING on %s:%s",
            self.config.proxy_host, self.config.proxy_port,
        )
        logger.info(
            "  Forwarding to %s://%s:%s",
            "https" if self.config.upstream_ssl else "http",
            self.config.upstream_host, self.config.upstream_port,
        )
        logger.info(
            "  Block threats: %s | Threshold: %.0f%%",
            self.config.block_threats, self.config.threat_threshold * 100,
        )
        logger.info(
            "═══════════════════════════════════════════════════"
        )
        logger.info(
            "HTTP  proxy  -> %s:%s  (upstream %s://%s:%s)",
            self.config.proxy_host, self.config.proxy_port,
            "https" if self.config.upstream_ssl else "http",
            self.config.upstream_host, self.config.upstream_port,
        )

        if self.config.ssl_certfile and self.config.ssl_keyfile:
            https_srv = _ThreadingHTTPServer(
                (self.config.proxy_host, self.config.proxy_ssl_port),
                _WAFProxyHandler,
            )
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(
                self.config.ssl_certfile,
                self.config.ssl_keyfile,
            )
            https_srv.socket = ctx.wrap_socket(
                https_srv.socket, server_side=True,
            )
            t = threading.Thread(target=https_srv.serve_forever, daemon=True)
            t.start()
            self._servers.append(https_srv)
            self._threads.append(t)
            logger.info(
                "HTTPS proxy  -> %s:%s  (TLS termination enabled)",
                self.config.proxy_host, self.config.proxy_ssl_port,
            )
        else:
            logger.info(
                "HTTPS proxy  disabled (no ssl_certfile / ssl_keyfile)."
            )
            logger.info(
                "  Generate with: openssl req -x509 -newkey rsa:2048 "
                "-keyout key.pem -out cert.pem -days 365 -nodes"
            )

    def _start_sniffer(self):
        try:
            from scapy.all import IP, Raw, TCP, sniff
            from scapy.layers.http import HTTP, HTTPRequest
            from scapy.packet import bind_layers
        except ImportError:
            self._running.clear()
            raise ImportError(
                "Sniffer mode requires scapy.  Install with:\n"
                "  pip install scapy\n"
                "On Windows you also need Npcap: https://npcap.com"
            )

        for port in self._http_ports():
            bind_layers(TCP, HTTP, sport=port)
            bind_layers(TCP, HTTP, dport=port)

        def _packet_cb(pkt):
            if not self._running.is_set():
                return

            try:
                self._process_packet(pkt, IP, TCP, Raw, HTTPRequest)
            except Exception as exc:
                if self.config.verbose:
                    logger.debug("Packet error: %s", exc)

        def _sniff_loop():
            iface = self.config.interface or None
            if self.config.loopback:
                lo = self._resolve_loopback_iface()
                if lo:
                    iface = lo
                    logger.info("Loopback capture enabled — adapter: %s", lo)
                else:
                    logger.warning(
                        "Loopback requested but no Npcap loopback adapter was found. "
                        "Reinstall Npcap with 'Support loopback traffic' enabled "
                        "(https://npcap.com), then run as administrator. "
                        "Falling back to the default interface — localhost traffic "
                        "will NOT be visible."
                    )

            bpf = None if self.config.loopback else self.config.sniff_filter

            logger.info("Sniffer on interface: %s", iface or "(default)")
            logger.info(
                "  HTTP ports inspected: %s",
                ", ".join(str(p) for p in sorted(self._http_ports())),
            )
            logger.info(
                "  HTTPS → metadata only (content is encrypted). "
                "Use proxy mode for full coverage."
            )
            try:
                sniff(
                    filter=bpf,
                    prn=_packet_cb,
                    store=False,
                    iface=iface,
                    stop_filter=lambda _: not self._running.is_set(),
                )
            except Exception as exc:
                logger.warning(
                    "Capture with BPF filter failed on this adapter (%s); "
                    "retrying without a kernel filter.", exc,
                )
                sniff(
                    prn=_packet_cb,
                    store=False,
                    iface=iface,
                    stop_filter=lambda _: not self._running.is_set(),
                )

        t = threading.Thread(target=_sniff_loop, daemon=True)
        t.start()
        self._threads.append(t)

    def _http_ports(self) -> set:
        """TCP ports from the sniff filter that should be decoded as HTTP."""
        ports = {int(m) for m in re.findall(r"port\s+(\d+)", self.config.sniff_filter)}
        return {p for p in ports if p not in (443, 8443)} or {80}

    @staticmethod
    def _resolve_loopback_iface() -> str:
        """Find the Npcap loopback adapter so localhost traffic is captured."""
        try:
            from scapy.all import conf
        except ImportError:
            return ""

        name = getattr(conf, "loopback_name", "") or ""
        if name:
            return name

        try:
            from scapy.arch.windows import get_windows_if_list
            for entry in get_windows_if_list():
                label = " ".join(
                    str(entry.get(k, "")) for k in ("name", "description")
                ).lower()
                if "loopback" in label:
                    return entry.get("name") or entry.get("description") or ""
        except Exception:
            pass

        return ""

    def _process_packet(self, pkt, IP, TCP, Raw, HTTPRequest):
        """Handle a single captured packet."""
        if pkt.haslayer(HTTPRequest):
            http_layer = pkt[HTTPRequest]
            host = (http_layer.Host.decode()
                    if http_layer.Host else "?")
            path = (http_layer.Path.decode()
                    if http_layer.Path else "/")
            method = (http_layer.Method.decode()
                      if http_layer.Method else "?")

            src_ip = pkt[IP].src if pkt.haslayer(IP) else "?"
            src_port = pkt[TCP].sport if pkt.haslayer(TCP) else 0

            body = ""
            if pkt.haslayer(Raw):
                body = pkt[Raw].load.decode("utf-8", errors="replace")
                if "\r\n\r\n" in body:
                    body = body.split("\r\n\r\n", 1)[1]

            self._inspect_http(method, host, path, body, src_ip, src_port)
            return

        if (pkt.haslayer(TCP) and pkt.haslayer(Raw)
                and pkt.haslayer(IP)):
            tcp = pkt[TCP]
            raw = bytes(pkt[Raw].load)

            if tcp.dport == 443 or tcp.sport == 443:
                if len(raw) > 5 and raw[0] == 0x16:
                    sni = self._extract_sni(raw)
                    src_ip = pkt[IP].src
                    with self._lock:
                        self._stats.https_encrypted += 1
                    if sni:
                        logger.info(
                            "HTTPS (encrypted) | %s -> %s  "
                            "[content not visible — use proxy mode]",
                            src_ip, sni,
                        )
                return

            parsed = self._parse_raw_http(raw)
            if parsed:
                method, host, path, body = parsed
                self._inspect_http(
                    method, host or "?", path, body, pkt[IP].src, tcp.sport
                )

    @staticmethod
    def _parse_raw_http(raw: bytes):
        """Extract (method, host, path, body) from a raw TCP payload, if it is HTTP."""
        methods = ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS")
        if not raw.startswith(tuple(m.encode() for m in methods)):
            return None
        try:
            text = raw.decode("utf-8", errors="replace")
        except Exception:
            return None

        head, _, body = text.partition("\r\n\r\n")
        lines = head.split("\r\n")
        if not lines:
            return None
        parts = lines[0].split(" ")
        if len(parts) < 3 or parts[0] not in methods or not parts[-1].startswith("HTTP/"):
            return None

        method, path = parts[0], " ".join(parts[1:-1])
        host = ""
        for line in lines[1:]:
            if line.lower().startswith("host:"):
                host = line.split(":", 1)[1].strip()
                break
        return method, host, path, body

    def _inspect_http(self, method, host, path, body, src_ip, src_port):
        """Classify the full request (method + URI + body) through the WAF model."""
        with self._lock:
            self._stats.total_requests += 1

        request_text = f"{method} {path} {body or ''}".strip()
        result = self._engine.analyze_decoded(request_text)
        threats: list[dict] = []
        if result["is_threat"] and result["confidence"] >= self.config.threat_threshold:
            threats.append(result)

        if threats:
            for t in threats:
                event = ThreatEvent(
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    source_ip=src_ip,
                    source_port=src_port,
                    method=method,
                    url=f"http://{host}{path}",
                    matched_payload=t["payload"][:200],
                    prediction=t["prediction"],
                    confidence=t["confidence"],
                    action="logged",
                )
                with self._lock:
                    self._threat_log.append(event)
                    self._stats.threats_detected += 1

                logger.warning(
                    "THREAT [%s] %.0f%% from %s | %s http://%s%s",
                    event.prediction, event.confidence * 100,
                    src_ip, method, host, path,
                )
                if self._on_threat:
                    try:
                        self._on_threat(event)
                    except Exception:
                        pass
        else:
            with self._lock:
                self._stats.safe_requests += 1
            if self.config.verbose:
                logger.debug("SAFE  | %s | %s http://%s%s",
                             src_ip, method, host, path)

    @staticmethod
    def _extract_sni(raw: bytes) -> str:
        """Parse the Server Name Indication from a TLS ClientHello."""
        try:
            if raw[0] != 0x16:
                return ""
            pos = 5
            if raw[pos] != 0x01:
                return ""
            pos += 4
            pos += 2 + 32
            sid_len = raw[pos]; pos += 1 + sid_len
            cs_len = int.from_bytes(raw[pos:pos+2], "big")
            pos += 2 + cs_len
            cm_len = raw[pos]; pos += 1 + cm_len
            if pos + 2 > len(raw):
                return ""
            ext_total = int.from_bytes(raw[pos:pos+2], "big")
            pos += 2
            end = pos + ext_total
            while pos + 4 < end and pos < len(raw):
                ext_type = int.from_bytes(raw[pos:pos+2], "big")
                ext_len  = int.from_bytes(raw[pos+2:pos+4], "big")
                pos += 4
                if ext_type == 0x0000:
                    name_len = int.from_bytes(raw[pos+3:pos+5], "big")
                    return raw[pos+5:pos+5+name_len].decode(
                        "ascii", errors="replace"
                    )
                pos += ext_len
        except (IndexError, ValueError):
            pass
        return ""

    def _setup_logging(self):
        if not logger.handlers and not logging.getLogger().handlers:
            sh = logging.StreamHandler()
            sh.setFormatter(logging.Formatter(
                "%(asctime)s [%(levelname)s] %(message)s",
                datefmt="%H:%M:%S",
            ))
            logger.addHandler(sh)

        logger.setLevel(
            logging.DEBUG if self.config.verbose else logging.INFO
        )

        if self.config.log_file:
            fh = logging.FileHandler(self.config.log_file)
            fh.setFormatter(logging.Formatter(
                "%(asctime)s [%(levelname)s] %(message)s",
            ))
            logger.addHandler(fh)
