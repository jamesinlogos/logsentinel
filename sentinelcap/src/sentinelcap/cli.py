"""sentinelcap -- CLI that collects labeled LogSentinel Sysmon telemetry sessions
(ransomware and goodware) from a VMware victim VM.

Run `sentinelcap --help` or `sentinelcap <subcommand> --help` for details.
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from sentinelcap import __version__
from sentinelcap.baseline import build_baseline
from sentinelcap.config import DEFAULT_CONFIG_TEMPLATE, SentinelcapConfig
from sentinelcap.logging_utils import configure_logging, get_logger
from sentinelcap.manifest import Mode, load_manifest, parse_row
from sentinelcap.orchestrate import run_batch, run_capture, run_session
from sentinelcap.vm import VMwareController

app = typer.Typer(add_completion=True, no_args_is_help=True, help=__doc__)
config_app = typer.Typer(no_args_is_help=True, help="Manage the config.yaml configuration file.")
vm_app = typer.Typer(
    no_args_is_help=True, help="Manually control the victim VM (revert/start/open-explorer/stop)."
)
build_app = typer.Typer(no_args_is_help=True, help="Prepare the victim VM snapshots.")
app.add_typer(config_app, name="config")
app.add_typer(vm_app, name="vm")
app.add_typer(build_app, name="build")

console = Console()
logger = get_logger("sentinelcap.cli")

ConfigOption = typer.Option(
    None, "--config", "-c", help="Path to config.yaml (default: ./config.yaml)."
)
VerboseOption = typer.Option(False, "--verbose", "-v", help="Enable debug-level logging.")
LogFileOption = typer.Option(None, "--log-file", help="Also write logs to this file.")


def _fail(what: str, error: Exception) -> typer.Exit:
    """Log a command failure (traceback with --verbose) and return the exit to raise."""
    logger.error("%s: %s", what, error)
    logger.debug("Traceback", exc_info=error)
    return typer.Exit(code=1)


def _load_config(config_path: Path | None) -> SentinelcapConfig:
    try:
        return SentinelcapConfig.load(config_path)
    except Exception as e:
        raise _fail("Failed to load configuration", e) from e


@app.callback(invoke_without_command=True)
def _root(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", help="Print the version and exit."),
    verbose: bool = VerboseOption,
    log_file: Path | None = LogFileOption,
) -> None:
    configure_logging(verbose=verbose, log_file=log_file)
    if version:
        console.print(f"sentinelcap {__version__}")
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        console.print(ctx.get_help())
        raise typer.Exit()


# --------------------------------------------------------------------------- config
@config_app.command("init")
def config_init(
    output: Path = typer.Option(
        Path("config.yaml"), "--output", "-o", help="Where to write the template config."
    ),
    force: bool = typer.Option(False, "--force", help="Overwrite the file if it already exists."),
) -> None:
    """Create a template config.yaml for editing."""
    if output.exists() and not force:
        logger.warning("%s already exists -- use --force to overwrite.", output)
        raise typer.Exit(code=1)
    output.write_text(DEFAULT_CONFIG_TEMPLATE, encoding="utf-8")
    logger.info("Created %s -- edit the values (especially guest_password) before use.", output)
    console.print(
        "[dim]Tip: override guest_password via an environment variable instead of "
        "storing it in the file:\n"
        "  PowerShell: $env:SENTINELCAP__VMWARE__GUEST_PASSWORD = '...'\n"
        "  cmd.exe:    set SENTINELCAP__VMWARE__GUEST_PASSWORD=...[/dim]"
    )


@config_app.command("show")
def config_show(config: Path | None = ConfigOption) -> None:
    """Print the resolved configuration (secrets redacted)."""
    cfg = _load_config(config)
    dumped = cfg.model_dump()
    dumped["vmware"]["guest_password"] = "***"
    console.print(dumped)


# --------------------------------------------------------------------------- vm
@vm_app.command("revert")
def vm_revert(config: Path | None = ConfigOption) -> None:
    """Revert the victim VM to its baseline snapshot."""
    cfg = _load_config(config)
    VMwareController(cfg.vmware).revert_to_baseline()


@vm_app.command("start")
def vm_start(config: Path | None = ConfigOption) -> None:
    """Start the VM and wait for VMware Tools to become ready."""
    cfg = _load_config(config)
    vm = VMwareController(cfg.vmware)
    vm.start()
    vm.wait_tools_ready()


@vm_app.command("stop")
def vm_stop(config: Path | None = ConfigOption) -> None:
    """Force-stop the VM after a collection session."""
    cfg = _load_config(config)
    VMwareController(cfg.vmware).stop_hard()


@vm_app.command("open-explorer")
def vm_open_explorer(
    directory: str = typer.Argument(..., help="Guest directory to open in File Explorer."),
    config: Path | None = ConfigOption,
) -> None:
    """Open a guest directory; launch samples manually from the VMware console."""
    cfg = _load_config(config)
    VMwareController(cfg.vmware).open_explorer(directory)


# --------------------------------------------------------------------------- capture
ForceOption = typer.Option(False, "--force", help="Overwrite an existing session directory.")
LabelOption = typer.Option(..., "--label", help="1 = ransomware, 0 = benign.")


@app.command()
def capture(
    family: str = typer.Option(..., "--family", "-f", help="e.g. idle, goodware."),
    sample: str = typer.Option(
        ..., "--sample", help="Session name, e.g. idle-01 (names the output directory)."
    ),
    label: str = LabelOption,
    duration: int = typer.Option(..., "--duration", help="Recording time in seconds."),
    force: bool = ForceOption,
    config: Path | None = ConfigOption,
) -> None:
    """Record the victim host for --duration seconds without touching the VM.

    Writes <out_dir>/<UTC timestamp>/<family>/<sample>/.
    """
    if duration <= 0:
        logger.error("--duration must be greater than zero.")
        raise typer.Exit(code=1)
    cfg = _load_config(config)
    try:
        entry = parse_row(
            {"family": family, "sample": sample, "path": None, "label": label}, Mode.CAPTURE
        )
        out_path = run_capture(cfg, entry, duration, force)
    except Exception as e:
        raise _fail("Capture failed", e) from e
    logger.info("Done -> %s", out_path)


# --------------------------------------------------------------------------- run / batch
ExecuteOption = typer.Option(
    False, "--execute", help="Operator double-clicks an executable in the VM."
)
InteractiveOption = typer.Option(
    False, "--interactive", help="Operator performs a scenario between two Enter presses."
)


def _resolve_mode(execute: bool, interactive: bool) -> Mode:
    if execute == interactive:
        logger.error("Pass exactly one of --execute or --interactive.")
        raise typer.Exit(code=1)
    return Mode.EXECUTE if execute else Mode.INTERACTIVE


@app.command()
def run(
    family: str = typer.Option(..., "--family", "-f", help="e.g. Akira, goodware."),
    sample: str = typer.Option(
        ...,
        "--sample",
        help="SHA-256 (--execute) or scenario name such as backup (--interactive).",
    ),
    label: str = LabelOption,
    path: str | None = typer.Option(
        None, "--path", "-p", help="Guest path of the executable (--execute only)."
    ),
    execute: bool = ExecuteOption,
    interactive: bool = InteractiveOption,
    force: bool = ForceOption,
    config: Path | None = ConfigOption,
) -> None:
    """Collect one session into <out_dir>/<UTC timestamp>/<family>/<sample>/."""
    mode = _resolve_mode(execute, interactive)
    cfg = _load_config(config)
    try:
        entry = parse_row({"family": family, "sample": sample, "path": path, "label": label}, mode)
        out_path = run_session(cfg, entry, mode, force)
    except Exception as e:
        raise _fail("Run failed", e) from e
    logger.info("Done -> %s", out_path)


@app.command()
def batch(
    manifest: Path = typer.Argument(..., help="CSV file with columns: family,sample,path,label."),
    execute: bool = ExecuteOption,
    interactive: bool = InteractiveOption,
    force: bool = ForceOption,
    config: Path | None = ConfigOption,
) -> None:
    """Collect every manifest row into one <out_dir>/<UTC timestamp>/; exit 1 if any row fails."""
    mode = _resolve_mode(execute, interactive)
    cfg = _load_config(config)
    try:
        entries = load_manifest(manifest, mode)
    except Exception as e:
        raise _fail("Failed to read manifest", e) from e

    logger.info("Loaded %d row(s) from %s.", len(entries), manifest)
    results = run_batch(cfg, entries, mode, force)

    table = Table(title="Batch results")
    table.add_column("Session")
    table.add_column("Result")
    table.add_column("Detail", overflow="fold")
    for result in results:
        table.add_row(
            result.entry.session_name,
            "[green]ok[/green]" if result.ok else "[red]FAILED[/red]",
            str(result.session_dir) if result.ok else str(result.error),
        )
    console.print(table)

    failed = sum(not r.ok for r in results)
    logger.info("Completed %d/%d session(s).", len(results) - failed, len(results))
    if failed:
        raise typer.Exit(code=1)


# --------------------------------------------------------------------------- build
@build_app.command("baseline")
def build_baseline_command(
    samples_dir: Path | None = typer.Option(
        None,
        "--samples-dir",
        help="Host directory with ransomware/<Family>/<sha256>.zip and goodware/<sha256>.exe.",
    ),
    seed: int | None = typer.Option(
        None, "--seed", help="Seed for directory and name choice (reproducible)."
    ),
    config: Path | None = ConfigOption,
) -> None:
    """Place every sample in the guest, save the baseline snapshot, write manifest.csv."""
    cfg = _load_config(config)
    try:
        rows = build_baseline(cfg, samples_dir=samples_dir, seed=seed)
    except Exception as e:
        raise _fail("Build baseline failed", e) from e
    logger.info(
        "Done: %d sample(s) placed, snapshot '%s' saved.", len(rows), cfg.vmware.baseline_snapshot
    )


if __name__ == "__main__":
    app()
