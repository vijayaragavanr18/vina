"""Unified aggregation layer for VINA web scanners.

Merges, normalises, and deduplicates outputs from all completed
web scanner stages into a single typed dataset.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..core.storage import JsonStore
from ..scanners.web.gau import GauResult
from ..scanners.web.httpx import HttpxResult
from ..scanners.web.katana import KatanaResult
from ..scanners.web.naabu import NaabuResult
from ..scanners.web.nmap import NmapResult
from ..scanners.web.recon import WebReconResult
from ..scanners.web.whatweb import WhatWebResult

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class AggregatedHost:
    """A single host discovered across scanners."""

    hostname: str
    ip: str | None = None
    ports: list[int] = field(default_factory=list)
    alive_urls: list[str] = field(default_factory=list)


@dataclass(slots=True)
class AggregatedEndpoint:
    """A single endpoint discovered by any crawler/scanner."""

    url: str
    host: str | None = None
    method: str | None = None
    status_code: int | None = None


@dataclass(slots=True)
class AggregatedTechnology:
    """A single technology/version pair detected on a host."""

    host: str
    name: str
    version: str | None = None
    categories: list[str] = field(default_factory=list)


@dataclass(slots=True)
class AggregatedService:
    """A single service detected on a host:port."""

    host: str
    port: int
    protocol: str = "tcp"
    service: str | None = None
    product: str | None = None
    version: str | None = None


@dataclass(slots=True)
class AggregatedResult:
    """Unified dataset produced by the Aggregator."""

    all_hosts: list[AggregatedHost] = field(default_factory=list)
    alive_hosts: list[str] = field(default_factory=list)
    services: list[AggregatedService] = field(default_factory=list)
    endpoints: list[AggregatedEndpoint] = field(default_factory=list)
    technologies: list[AggregatedTechnology] = field(default_factory=list)
    historical_urls: list[str] = field(default_factory=list)


class Aggregator:
    """Merge and deduplicate data from all web scanner stages."""

    def __init__(self, output_dir: Path) -> None:
        self.store = JsonStore(output_dir)

    async def run(
        self,
        subfinder: WebReconResult,
        httpx: HttpxResult,
        naabu: NaabuResult,
        nmap: NmapResult,
        whatweb: WhatWebResult,
        katana: KatanaResult,
        gau: GauResult,
    ) -> AggregatedResult:
        """Merge all scanner results into a single AggregatedResult."""

        # -- Hosts (all unique hostnames across scanners) ---------------
        all_hosts = self._merge_hosts(subfinder, httpx, naabu, nmap, whatweb, katana, gau)

        # -- Alive hosts (URLs from httpx) ------------------------------
        alive_hosts = self._merge_alive_hosts(httpx)

        # -- Services (naabu open_ports + nmap services) ----------------
        services = self._merge_services(naabu, nmap)

        # -- Endpoints (katana) -----------------------------------------
        endpoints = self._merge_endpoints(katana)

        # -- Technologies (whatweb + httpx) -----------------------------
        technologies = self._merge_technologies(whatweb, httpx)

        # -- Historical URLs (gau) --------------------------------------
        historical_urls = self._merge_historical_urls(gau)

        result = AggregatedResult(
            all_hosts=all_hosts,
            alive_hosts=alive_hosts,
            services=services,
            endpoints=endpoints,
            technologies=technologies,
            historical_urls=historical_urls,
        )

        self._save_results(result)
        self._print_summary(result)
        return result

    # -- Merge helpers ---------------------------------------------------

    @staticmethod
    def _merge_hosts(
        subfinder: WebReconResult,
        httpx: HttpxResult,
        naabu: NaabuResult,
        nmap: NmapResult,
        whatweb: WhatWebResult,
        katana: KatanaResult,
        gau: GauResult,
    ) -> list[AggregatedHost]:
        """Collect every unique hostname into AggregatedHost entries."""
        host_map: dict[str, AggregatedHost] = {}

        def _ensure(hostname: str) -> AggregatedHost:
            key = hostname.lower()
            if key not in host_map:
                host_map[key] = AggregatedHost(hostname=hostname)
            return host_map[key]

        def _ip(hostname: str, ip: str | None) -> None:
            if ip:
                h = _ensure(hostname)
                h.ip = ip

        def _port(hostname: str, port: int) -> None:
            h = _ensure(hostname)
            if port not in h.ports:
                h.ports.append(port)

        def _alive(hostname: str, url: str) -> None:
            h = _ensure(hostname)
            if url not in h.alive_urls:
                h.alive_urls.append(url)

        # Subfinder subdomains
        for sub in subfinder.subdomains:
            _ensure(sub)

        # Httpx records
        for rec in httpx.records:
            h = _ensure(rec.host)
            if rec.ip:
                h.ip = rec.ip
            if rec.url not in h.alive_urls:
                h.alive_urls.append(rec.url)

        # Naabu records
        for port_str in naabu.open_ports:
            host = Aggregator._parse_open_port_host(port_str)
            port = Aggregator._parse_open_port_port(port_str)
            if host and port is not None:
                _port(host, port)

        # Nmap hosts
        for nh in nmap.hosts:
            h = _ensure(nh.hostname)
            if nh.ip:
                h.ip = nh.ip
            for svc in nh.services:
                if svc.port not in h.ports:
                    h.ports.append(svc.port)

        # WhatWeb hosts
        for wh in whatweb.hosts:
            if wh.host:
                _ensure(wh.host)

        # Katana endpoints
        for ep in katana.endpoints:
            if ep.host:
                _ensure(ep.host)

        # Gau URLs
        for gu in gau.urls:
            if gu.host:
                _ensure(gu.host)

        result = sorted(host_map.values(), key=lambda h: h.hostname)
        for h in result:
            h.ports.sort()
            h.alive_urls.sort()
        return result

    @staticmethod
    def _merge_alive_hosts(httpx: HttpxResult) -> list[str]:
        """Collect unique alive URLs from httpx."""
        seen: set[str] = set()
        result: list[str] = []
        for url in httpx.alive_hosts:
            key = url.lower()
            if key not in seen:
                seen.add(key)
                result.append(url)
        return result

    @staticmethod
    def _merge_services(naabu: NaabuResult, nmap: NmapResult) -> list[AggregatedService]:
        """Merge services from Naabu (port/protocol) and Nmap (with versions)."""
        seen: set[tuple[str, int, str]] = set()
        services: list[AggregatedService] = []

        # Naabu open ports
        for port_str in naabu.open_ports:
            host = Aggregator._parse_open_port_host(port_str)
            port = Aggregator._parse_open_port_port(port_str)
            protocol = Aggregator._parse_open_port_protocol(port_str)
            if host and port is not None:
                key = (host.lower(), port, protocol)
                if key not in seen:
                    seen.add(key)
                    services.append(AggregatedService(host=host, port=port, protocol=protocol))

        # Nmap services (override Naabu when version info exists)
        for svc in nmap.services:
            key = (svc.hostname.lower(), svc.port, svc.protocol)
            if key not in seen:
                seen.add(key)
                services.append(
                    AggregatedService(
                        host=svc.hostname,
                        port=svc.port,
                        protocol=svc.protocol,
                        service=svc.service,
                        product=svc.product,
                        version=svc.version,
                    )
                )
            else:
                # Prefer version-enriched record from Nmap
                for existing in services:
                    if (
                        existing.host.lower() == svc.hostname.lower()
                        and existing.port == svc.port
                        and existing.protocol == svc.protocol
                    ):
                        existing.service = svc.service or existing.service
                        existing.product = svc.product or existing.product
                        existing.version = svc.version or existing.version
                        break

        services.sort(key=lambda s: (s.host.lower(), s.port, s.protocol))
        return services

    @staticmethod
    def _merge_endpoints(katana: KatanaResult) -> list[AggregatedEndpoint]:
        """Collect endpoints from Katana, deduplicated by URL."""
        seen: set[str] = set()
        endpoints: list[AggregatedEndpoint] = []
        for ep in katana.endpoints:
            key = ep.url.lower()
            if key not in seen:
                seen.add(key)
                endpoints.append(
                    AggregatedEndpoint(url=ep.url, host=ep.host, method=ep.method, status_code=ep.status_code)
                )
        endpoints.sort(key=lambda e: e.url.lower())
        return endpoints

    @staticmethod
    def _merge_technologies(whatweb: WhatWebResult, httpx: HttpxResult) -> list[AggregatedTechnology]:
        """Merge technology detections from WhatWeb and httpx."""
        seen: set[tuple[str, str]] = set()
        technologies: list[AggregatedTechnology] = []

        # WhatWeb technologies (richer data)
        for wh in whatweb.hosts:
            host = wh.host or wh.url
            for tech in wh.technologies:
                key = (host.lower(), tech.name.lower())
                if key not in seen:
                    seen.add(key)
                    technologies.append(
                        AggregatedTechnology(
                            host=host, name=tech.name, version=tech.version, categories=tech.categories
                        )
                    )

        # httpx technologies (simple name only)
        for rec in httpx.records:
            for tech_name in rec.technologies:
                key = (rec.host.lower(), tech_name.lower())
                if key not in seen:
                    seen.add(key)
                    technologies.append(AggregatedTechnology(host=rec.host, name=tech_name))

        technologies.sort(key=lambda t: (t.host.lower(), t.name.lower()))
        return technologies

    @staticmethod
    def _merge_historical_urls(gau: GauResult) -> list[str]:
        """Collect historical URLs from GAU, deduplicated."""
        seen: set[str] = set()
        urls: list[str] = []
        for gu in gau.urls:
            key = gu.url.lower()
            if key not in seen:
                seen.add(key)
                urls.append(gu.url)
        urls.sort(key=str.lower)
        return urls

    # -- Open-port string helpers ---------------------------------------

    @staticmethod
    def _parse_open_port_host(port_str: str) -> str | None:
        if "/" not in port_str or ":" not in port_str:
            return None
        host_part, _ = port_str.rsplit(":", 1)
        host = host_part.strip().lower()
        return host or None

    @staticmethod
    def _parse_open_port_port(port_str: str) -> int | None:
        if "/" not in port_str or ":" not in port_str:
            return None
        _, rest = port_str.rsplit(":", 1)
        port_part, _ = rest.split("/", 1)
        try:
            return int(port_part)
        except ValueError:
            return None

    @staticmethod
    def _parse_open_port_protocol(port_str: str) -> str:
        if "/" not in port_str:
            return "tcp"
        _, rest = port_str.rsplit(":", 1)
        if "/" not in rest:
            return "tcp"
        _, protocol = rest.split("/", 1)
        return protocol.strip().lower() or "tcp"

    # -- Save / print ----------------------------------------------------

    def _save_results(self, result: AggregatedResult) -> Path:
        payload = {
            "all_hosts": [self._host_to_dict(h) for h in result.all_hosts],
            "alive_hosts": result.alive_hosts,
            "services": [self._service_to_dict(s) for s in result.services],
            "endpoints": [self._endpoint_to_dict(e) for e in result.endpoints],
            "technologies": [self._technology_to_dict(t) for t in result.technologies],
            "historical_urls": result.historical_urls,
        }
        return self.store.save("web/summary.json", payload)

    @staticmethod
    def _host_to_dict(h: AggregatedHost) -> dict[str, Any]:
        return {"hostname": h.hostname, "ip": h.ip, "ports": h.ports, "alive_urls": h.alive_urls}

    @staticmethod
    def _service_to_dict(s: AggregatedService) -> dict[str, Any]:
        return {
            "host": s.host,
            "port": s.port,
            "protocol": s.protocol,
            "service": s.service,
            "product": s.product,
            "version": s.version,
        }

    @staticmethod
    def _endpoint_to_dict(e: AggregatedEndpoint) -> dict[str, Any]:
        return {"url": e.url, "host": e.host, "method": e.method, "status_code": e.status_code}

    @staticmethod
    def _technology_to_dict(t: AggregatedTechnology) -> dict[str, Any]:
        return {"host": t.host, "name": t.name, "version": t.version, "categories": t.categories}

    def _print_summary(self, result: AggregatedResult) -> None:
        print("----------------------------------------")
        print("VINA Aggregator")
        print("----------------------------------------")
        print(f"Hosts         : {len(result.all_hosts)}")
        print(f"Alive Hosts   : {len(result.alive_hosts)}")
        print(f"Endpoints     : {len(result.endpoints)}")
        print(f"Services      : {len(result.services)}")
        print(f"Tech Stack    : {len(result.technologies)}")
        print(f"URLs          : {len(result.historical_urls)}")


__all__ = [
    "AggregatedEndpoint",
    "AggregatedHost",
    "AggregatedResult",
    "AggregatedService",
    "AggregatedTechnology",
    "Aggregator",
]
