"""Best-effort parsers for command output."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable


def lines(output: str) -> list[str]:
    return [line.strip() for line in output.splitlines() if line.strip()]


def unique_lines(output: str) -> list[str]:
    seen: set[str] = set()
    results: list[str] = []
    for line in lines(output):
        if line not in seen:
            seen.add(line)
            results.append(line)
    return results


def parse_json_lines(output: str) -> list[dict[str, object]]:
    parsed: list[dict[str, object]] = []
    for line in lines(output):
        if line.startswith("{"):
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                parsed.append(value)
    return parsed


def parse_urls(output: str) -> list[str]:
    url_pattern = re.compile(r"https?://[^\s\"'<>]+")
    found: list[str] = []
    seen: set[str] = set()
    for line in lines(output):
        matches = url_pattern.findall(line)
        if matches:
            for match in matches:
                if match not in seen:
                    seen.add(match)
                    found.append(match)
        elif line.startswith(("http://", "https://")) and line not in seen:
            seen.add(line)
            found.append(line)
    return found


def parse_katana(output: str) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    for item in parse_json_lines(output):
        url = item.get("url") or item.get("request") or item.get("source")
        if isinstance(url, str):
            results.append({"url": url, "source": item})
    return results


def parse_httpx(output: str) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    for item in parse_json_lines(output):
        url = item.get("url") or item.get("input") or item.get("host")
        if isinstance(url, str):
            results.append(item)
    return results


def parse_naabu(output: str) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    for item in parse_json_lines(output):
        host = item.get("host")
        port = item.get("port")
        if isinstance(host, str) and isinstance(port, int):
            results.append(item)
    return results


def parse_nuclei(output: str) -> list[dict[str, object]]:
    return parse_json_lines(output)


def parse_whatweb(output: str) -> list[dict[str, object]]:
    return parse_json_lines(output)


def parse_nmap_grepable(output: str) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    pattern = re.compile(r"Ports:\s*(?P<data>.+)")
    for line in lines(output):
        match = pattern.search(line)
        if not match:
            continue
        for port_blob in match.group("data").split(","):
            fields = port_blob.split("/")
            if len(fields) >= 5:
                port, state, protocol, _, service = fields[:5]
                if state == "open" and port.isdigit():
                    results.append({"host": None, "port": int(port), "protocol": protocol, "service": service})
    return results


def flatten_unique(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result
