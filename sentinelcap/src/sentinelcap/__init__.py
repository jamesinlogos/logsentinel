"""sentinelcap -- CLI that collects labeled LogSentinel Sysmon telemetry sessions
(ransomware and goodware) from a VMware victim VM."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("sentinelcap")  # single source: pyproject.toml
except PackageNotFoundError:  # running from a source tree without `pip install -e .`
    __version__ = "0+unknown"
