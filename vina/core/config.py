"""Configuration loading and validation for VINA.

This module loads YAML configuration, validates it with Pydantic, and
exposes a backward-compatible configuration object for the rest of the
application.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator


class ConfigurationError(ValueError):
    """Raised when the configuration file is missing or invalid."""


DEFAULT_COMMON_PORTS = [80, 443, 8080, 8443]
DEFAULT_TOOL_BINS: dict[str, str] = {
    "subfinder": "subfinder",
    "assetfinder": "assetfinder",
    "amass": "amass",
    "httpx": "httpx",
    "naabu": "naabu",
    "nmap": "nmap",
    "whatweb": "WhatWeb",
    "katana": "katana",
    "gau": "gau",
    "waybackurls": "waybackurls",
    "gf": "gf",
    "qsreplace": "qsreplace",
    "uro": "uro",
    "nuclei": "nuclei",
    "dalfox": "dalfox",
    "ffuf": "ffuf",
    "find": "find",
    "getcap": "getcap",
    "capsh": "capsh",
    "systemctl": "systemctl",
    "journalctl": "journalctl",
    "auditctl": "auditctl",
    "ausearch": "ausearch",
    "sysctl": "sysctl",
    "checksec": "checksec",
    "mokutil": "mokutil",
    "sestatus": "sestatus",
    "getenforce": "getenforce",
    "aa-status": "aa-status",
    "readelf": "readelf",
    "objdump": "objdump",
    "strings": "strings",
    "ldd": "ldd",
    "nm": "nm",
    "stat": "stat",
    "mount": "mount",
    "lsblk": "lsblk",
    "df": "df",
    "lsmod": "lsmod",
    "modinfo": "modinfo",
}


def _project_root() -> Path:
    """Return the repository root."""

    return Path(__file__).resolve().parents[2]


def _default_output_dir() -> Path:
    """Return the default output directory."""

    return _project_root() / "output"


def _default_log_dir() -> Path:
    """Return the default log directory."""

    return _project_root() / "logs"


def _default_config_path() -> Path:
    """Return the repository-default configuration file path."""

    return _project_root() / "config.yaml"


class RunnerSettings(BaseModel):
    """Runtime settings for subprocess execution."""

    model_config = ConfigDict(extra="forbid")

    timeout_seconds: int = 60
    concurrency: int = 4
    stdout_limit_bytes: int = 10 * 1024 * 1024
    stderr_limit_bytes: int = 10 * 1024 * 1024

    @field_validator("timeout_seconds", "concurrency", "stdout_limit_bytes", "stderr_limit_bytes")
    @classmethod
    def _validate_positive_int(cls, value: int) -> int:
        """Ensure runner settings are positive integers."""

        if int(value) <= 0:
            raise ValueError("runner settings must be greater than 0")
        return int(value)


class OutputSettings(BaseModel):
    """Settings that control where analysis artifacts are written."""

    model_config = ConfigDict(extra="forbid")

    output_dir: Path = Field(default_factory=_default_output_dir)

    @field_validator("output_dir", mode="before")
    @classmethod
    def _coerce_path(cls, value: Any) -> Path:
        """Coerce path-like values into Path instances."""

        if isinstance(value, Path):
            return value
        if isinstance(value, str):
            return Path(value)
        raise TypeError("output_dir must be a string or pathlib.Path instance")


class LoggingSettings(BaseModel):
    """Settings that control logging destinations and formatting."""

    model_config = ConfigDict(extra="forbid")

    log_dir: Path = Field(default_factory=_default_log_dir)
    level: str = "INFO"
    file_name: str = "vina.log"

    @field_validator("log_dir", mode="before")
    @classmethod
    def _coerce_log_dir(cls, value: Any) -> Path:
        """Coerce path-like logging directories into Path instances."""

        if isinstance(value, Path):
            return value
        if isinstance(value, str):
            return Path(value)
        raise TypeError("log_dir must be a string or pathlib.Path instance")

    @field_validator("level")
    @classmethod
    def _validate_level(cls, value: str) -> str:
        """Normalize and validate the logging level."""

        normalized = value.strip().upper()
        valid_levels = {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET"}
        if normalized not in valid_levels:
            raise ValueError(f"Invalid logging level: {value}")
        return normalized

    @field_validator("file_name")
    @classmethod
    def _validate_file_name(cls, value: str) -> str:
        """Ensure the log file name is non-empty."""

        normalized = value.strip()
        if not normalized:
            raise ValueError("log file name must not be empty")
        return normalized


class ToolSettings(BaseModel):
    """Executable path configuration for all external tools."""

    model_config = ConfigDict(extra="forbid")

    paths: dict[str, str] = Field(default_factory=lambda: dict(DEFAULT_TOOL_BINS))

    @field_validator("paths")
    @classmethod
    def _validate_paths(cls, value: Mapping[str, Any]) -> dict[str, str]:
        """Normalize the tool-path mapping."""

        if not value:
            raise ValueError("tool paths must not be empty")
        normalized: dict[str, str] = {}
        for key, tool_path in value.items():
            key_text = str(key).strip()
            path_text = str(tool_path).strip()
            if not key_text:
                raise ValueError("tool paths contains an empty key")
            if not path_text:
                raise ValueError(f"tool path for {key_text!r} is empty")
            normalized[key_text] = path_text
        return normalized


class Config(BaseModel):
    """Validated VINA configuration.

    The model keeps the existing flat runtime attributes available through
    compatibility properties while storing the configuration in structured
    sections.
    """

    model_config = ConfigDict(extra="forbid")

    runner: RunnerSettings = Field(default_factory=RunnerSettings)
    output: OutputSettings = Field(default_factory=OutputSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)
    tools: ToolSettings = Field(default_factory=ToolSettings)
    common_ports: list[int] = Field(default_factory=lambda: list(DEFAULT_COMMON_PORTS))

    @field_validator("common_ports")
    @classmethod
    def _validate_ports(cls, value: list[int]) -> list[int]:
        """Validate and normalize the common-port list."""

        if not value:
            raise ValueError("common_ports must not be empty")
        normalized: list[int] = []
        seen: set[int] = set()
        for port in value:
            port_value = int(port)
            if not 1 <= port_value <= 65535:
                raise ValueError(f"Invalid port number: {port_value}")
            if port_value not in seen:
                seen.add(port_value)
                normalized.append(port_value)
        return normalized

    @property
    def output_dir(self) -> Path:
        """Backward-compatible access to the output directory."""

        return self.output.output_dir

    @property
    def log_dir(self) -> Path:
        """Backward-compatible access to the logging directory."""

        return self.logging.log_dir

    @property
    def log_level(self) -> str:
        """Backward-compatible access to the configured logging level."""

        return self.logging.level

    @property
    def log_file_name(self) -> str:
        """Backward-compatible access to the configured log file name."""

        return self.logging.file_name

    @property
    def timeout_seconds(self) -> int:
        """Backward-compatible access to the default runner timeout."""

        return self.runner.timeout_seconds

    @property
    def concurrency(self) -> int:
        """Backward-compatible access to the runner concurrency setting."""

        return self.runner.concurrency

    @property
    def stdout_limit_bytes(self) -> int:
        """Backward-compatible access to the stdout memory limit."""

        return self.runner.stdout_limit_bytes

    @property
    def stderr_limit_bytes(self) -> int:
        """Backward-compatible access to the stderr memory limit."""

        return self.runner.stderr_limit_bytes

    @property
    def tool_bins(self) -> dict[str, str]:
        """Backward-compatible access to the configured tool paths."""

        return self.tools.paths

    @classmethod
    def load(cls, config_path: str | Path | None = None) -> Config:
        """Load and validate configuration from YAML."""

        return load_config(config_path, model_cls=cls)

    def tool_bin(self, name: str, default: str | None = None) -> str:
        """Return the executable configured for a logical tool name."""

        return self.tools.paths.get(name, default or name)


class AppConfig(Config):
    """Backward-compatible alias for legacy imports."""


def _load_yaml_document(config_path: Path) -> dict[str, Any]:
    """Load a YAML document from disk and return it as a mapping."""

    try:
        raw_text = config_path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ConfigurationError(f"Configuration file not found: {config_path}") from exc
    except OSError as exc:
        raise ConfigurationError(f"Unable to read configuration file {config_path}: {exc}") from exc

    try:
        loaded = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        raise ConfigurationError(f"Invalid YAML in configuration file {config_path}: {exc}") from exc

    if loaded is None:
        return {}
    if not isinstance(loaded, dict):
        raise ConfigurationError(f"Configuration file {config_path} must contain a YAML mapping at the top level")
    return loaded


def _resolve_relative_path(value: Path, base_dir: Path) -> Path:
    """Resolve a path relative to the configuration file location when needed."""

    return value if value.is_absolute() else base_dir / value


def _section(raw: Mapping[str, Any], name: str) -> dict[str, Any]:
    """Return a section mapping if it exists and is a mapping."""

    value = raw.get(name)
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ConfigurationError(f"Configuration section '{name}' must be a mapping")
    return dict(value)


def _merge_tool_paths(raw: Mapping[str, Any]) -> dict[str, str]:
    """Merge tool path data from nested and flat configuration layouts."""

    merged = dict(DEFAULT_TOOL_BINS)
    flat_tool_bins = raw.get("tool_bins")
    flat_tool_paths = raw.get("tool_paths")
    nested_tools = _section(raw, "tools")
    nested_paths = nested_tools.get("paths") if nested_tools else None

    for source in (flat_tool_bins, flat_tool_paths, nested_paths):
        if source is None:
            continue
        if not isinstance(source, Mapping):
            raise ConfigurationError("tool path configuration must be a mapping")
        for key, value in source.items():
            key_text = str(key).strip()
            path_text = str(value).strip()
            if not key_text:
                raise ConfigurationError("tool path configuration contains an empty key")
            if not path_text:
                raise ConfigurationError(f"tool path for {key_text!r} is empty")
            merged[key_text] = path_text
    return merged


def _normalize_config(raw: Mapping[str, Any], base_dir: Path) -> dict[str, Any]:
    """Normalize flat or nested YAML data into the structured Config schema."""

    runner_section = _section(raw, "runner")
    output_section = _section(raw, "output")
    logging_section = _section(raw, "logging")

    runner_data = {
        "timeout_seconds": runner_section.get("timeout_seconds", raw.get("timeout_seconds", 60)),
        "concurrency": runner_section.get("concurrency", raw.get("concurrency", 4)),
        "stdout_limit_bytes": runner_section.get("stdout_limit_bytes", raw.get("stdout_limit_bytes", 10 * 1024 * 1024)),
        "stderr_limit_bytes": runner_section.get("stderr_limit_bytes", raw.get("stderr_limit_bytes", 10 * 1024 * 1024)),
    }

    output_dir_value = output_section.get("output_dir", raw.get("output_dir", _default_output_dir()))
    log_dir_value = logging_section.get("log_dir", raw.get("log_dir", _default_log_dir()))

    logging_data = {
        "log_dir": _resolve_relative_path(Path(log_dir_value), base_dir),
        "level": logging_section.get("level", raw.get("log_level", "INFO")),
        "file_name": logging_section.get("file_name", raw.get("log_file_name", "vina.log")),
    }

    return {
        "runner": runner_data,
        "output": {
            "output_dir": _resolve_relative_path(Path(output_dir_value), base_dir),
        },
        "logging": logging_data,
        "tools": {
            "paths": _merge_tool_paths(raw),
        },
        "common_ports": raw.get("common_ports", list(DEFAULT_COMMON_PORTS)),
    }


def load_config(config_path: str | Path | None = None, *, model_cls: type[Config] = Config) -> Config:
    """Load configuration from YAML and validate it with Pydantic.

    Parameters
    ----------
    config_path:
        Optional override for the configuration file path. If omitted, the
        repository root ``config.yaml`` is loaded.
    model_cls:
        Internal hook used by :meth:`Config.load` so the same loader can return
        subclasses when needed.

    Returns
    -------
    Config
        A validated configuration object.

    Raises
    ------
    ConfigurationError
        If the file is missing, malformed, or invalid.
    """

    path = Path(config_path) if config_path is not None else _default_config_path()
    raw = _load_yaml_document(path)
    normalized = _normalize_config(raw, path.parent)

    try:
        return model_cls.model_validate(normalized)
    except ValidationError as exc:
        raise ConfigurationError(f"Invalid configuration in {path}: {exc}") from exc


__all__ = ["AppConfig", "Config", "ConfigurationError", "load_config"]
