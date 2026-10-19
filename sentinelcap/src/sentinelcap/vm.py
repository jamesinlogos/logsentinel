"""Wrapper around vmrun.exe for controlling the victim VM's lifecycle from Python."""

from __future__ import annotations

import base64
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from sentinelcap.config import VMwareConfig
from sentinelcap.errors import SentinelcapError
from sentinelcap.logging_utils import get_logger

logger = get_logger(__name__)

GUEST_TMP_DIR = r"C:\Windows\Temp"
"""Existing guest directory for transient files (sample zips, directory listings)."""
GUEST_POWERSHELL_PATH = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
GUEST_DIR_LISTING_PATH = GUEST_TMP_DIR + r"\sentinelcap-dirs.txt"


class VMwareError(SentinelcapError):
    """Raised when a vmrun invocation fails or a VM operation times out."""


def encode_powershell(script: str) -> str:
    """Base64 UTF-16LE form for ``powershell -EncodedCommand`` (no quoting issues)."""
    return base64.b64encode(script.encode("utf-16-le")).decode("ascii")


def ps_literal(value: str) -> str:
    """PowerShell single-quoted string literal (no expansion; spaces are safe)."""
    return "'" + value.replace("'", "''") + "'"


@dataclass
class VMwareController:
    cfg: VMwareConfig

    @staticmethod
    def _display_args(args: list[str]) -> list[str]:
        """Return command arguments with guest credentials redacted."""
        display = args.copy()
        if "-gp" in display:
            password_index = display.index("-gp") + 1
            if password_index < len(display):
                display[password_index] = "***"
        return display

    def _run(self, args: list[str], check: bool = True) -> subprocess.CompletedProcess:
        cmd = [self.cfg.vmrun_path, "-T", "ws", *args]
        display_cmd = self._display_args(cmd)
        logger.debug("$ %s", " ".join(a if " " not in a else repr(a) for a in display_cmd))
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if result.stdout.strip():
            logger.debug(result.stdout.strip())
        if check and result.returncode != 0:
            raise VMwareError(
                f"vmrun failed (exit={result.returncode}): {' '.join(self._display_args(args))}\n"
                f"{result.stdout}{result.stderr}"
            )
        return result

    def _run_guest(self, args: list[str], check: bool = True) -> subprocess.CompletedProcess:
        return self._run(
            ["-gu", self.cfg.guest_user, "-gp", self.cfg.guest_password, *args], check=check
        )

    # ------------------------------------------------------------------ power / snapshots
    def revert_to(self, name: str) -> None:
        logger.info("Reverting to snapshot '%s'...", name)
        self._run(["revertToSnapshot", self.cfg.vmx_path, name])

    def revert_to_baseline(self) -> None:
        """Revert to the baseline snapshot used by every collection session."""
        self.revert_to(self.cfg.baseline_snapshot)

    def list_snapshots(self) -> list[str]:
        result = self._run(["listSnapshots", self.cfg.vmx_path])
        lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        return [line for line in lines if not line.lower().startswith("total snapshots")]

    def delete_snapshot(self, name: str) -> None:
        """Delete ``name`` if present; raise if it still exists afterwards."""
        logger.info("Deleting snapshot '%s' (if present)...", name)
        self._run(["deleteSnapshot", self.cfg.vmx_path, name], check=False)
        if name in self.list_snapshots():
            raise VMwareError(
                f"Snapshot '{name}' still exists after deleteSnapshot; refusing to create "
                "a second one with the same name"
            )

    def create_snapshot(self, name: str) -> None:
        logger.info("Creating snapshot '%s'...", name)
        self._run(["snapshot", self.cfg.vmx_path, name])

    def start(self) -> None:
        logger.info("Starting VM...")
        self._run(["start", self.cfg.vmx_path, "nogui"])

    def stop_hard(self) -> None:
        logger.info("Force-stopping VM...")
        self._run(["stop", self.cfg.vmx_path, "hard"], check=False)

    def wait_tools_ready(self) -> None:
        logger.info("Waiting for VMware Tools to become ready in the guest...")
        deadline = time.monotonic() + self.cfg.tools_ready_timeout_sec
        while time.monotonic() < deadline:
            result = self._run(["checkToolsState", self.cfg.vmx_path], check=False)
            if "running" in result.stdout.lower():
                logger.info("VMware Tools is ready.")
                return
            time.sleep(5)
        raise VMwareError("VMware Tools did not become ready before the timeout.")

    # ------------------------------------------------------------------ guest operations
    def copy_to_guest(self, host_path: str | Path, guest_path: str) -> None:
        self._run_guest(["copyFileFromHostToGuest", self.cfg.vmx_path, str(host_path), guest_path])

    def copy_from_guest(self, guest_path: str, host_path: str | Path) -> None:
        self._run_guest(["copyFileFromGuestToHost", self.cfg.vmx_path, guest_path, str(host_path)])

    def file_exists_in_guest(self, guest_path: str) -> bool:
        result = self._run_guest(["fileExistsInGuest", self.cfg.vmx_path, guest_path], check=False)
        return result.returncode == 0 and "does not exist" not in result.stdout.lower()

    def rename_file_in_guest(self, old_path: str, new_path: str) -> None:
        """vmrun's own rename: no guest shell, no argument quoting."""
        self._run_guest(["renameFileInGuest", self.cfg.vmx_path, old_path, new_path])

    def delete_file_in_guest(self, guest_path: str) -> None:
        self._run_guest(["deleteFileInGuest", self.cfg.vmx_path, guest_path])

    def run_in_guest(
        self, program: str, *args: str, wait: bool = True
    ) -> subprocess.CompletedProcess:
        """Run ``program`` in the interactive guest session; raise on a non-zero exit.

        vmrun joins the arguments into one guest command line, and quotes added
        on the host do not keep an argument with whitespace in one piece (7-Zip
        with ``-o...\\Saved Games`` extracts elsewhere). Such arguments are
        therefore refused: pass them inside a script with ``run_powershell``.
        """
        if any(c.isspace() for arg in args for c in arg):
            raise ValueError(
                f"guest arguments must not contain whitespace, got {args!r}; use run_powershell"
            )
        flags = ["-interactive"] if wait else ["-noWait", "-interactive"]
        return self._run_guest(["runProgramInGuest", self.cfg.vmx_path, *flags, program, *args])

    def run_powershell(self, script: str) -> subprocess.CompletedProcess:
        """Run a PowerShell script in the guest via ``-EncodedCommand``.

        The script travels base64-encoded, so paths with spaces never go through
        the command line that vmrun builds; quote them inside the script with
        ``ps_literal``.
        """
        return self.run_in_guest(
            GUEST_POWERSHELL_PATH,
            "-NoProfile",
            "-NonInteractive",
            "-WindowStyle",
            "Hidden",
            "-EncodedCommand",
            encode_powershell(script),
        )

    def read_guest_text(self, guest_path: str) -> str:
        """Copy a small guest text file to the host and return its content."""
        with tempfile.TemporaryDirectory() as tmp:
            host_copy = Path(tmp) / "guest.txt"
            self.copy_from_guest(guest_path, host_copy)
            return host_copy.read_text(encoding="utf-8-sig", errors="replace")

    def list_dirs_in_guest(self, roots: list[str]) -> list[str]:
        """Existing, non-hidden sub-directories under ``roots`` (recursive), as guest paths.

        Unreadable or missing roots are skipped; the script always exits 0
        because ``powershell -EncodedCommand`` exits 1 after any non-terminating
        error even with ``-ErrorAction SilentlyContinue``. A listing that was not
        written makes the copy back fail.
        """
        listing = GUEST_DIR_LISTING_PATH
        script = (
            f"Get-ChildItem -LiteralPath {','.join(ps_literal(r) for r in roots)} "
            "-Directory -Recurse -ErrorAction SilentlyContinue | "
            "ForEach-Object { $_.FullName } | "
            f"Set-Content -Encoding UTF8 -LiteralPath {ps_literal(listing)}; exit 0"
        )
        self.run_powershell(script)
        text = self.read_guest_text(listing)
        self.delete_file_in_guest(listing)
        return [line.strip() for line in text.splitlines() if line.strip()]

    def open_explorer(self, guest_directory: str) -> None:
        """Open a guest directory for the operator to launch a sample manually.

        SentinelCap deliberately never starts a sample executable. The
        operator performs the click from the interactive guest desktop so the
        collection preserves genuine Windows Shell execution context.
        """
        logger.info("Opening File Explorer in guest: %s", guest_directory)
        # Started from an encoded script so that directories such as "3D Objects"
        # reach Explorer as one argument (see run_in_guest).
        quoted_directory = f'"{guest_directory}"'
        script = (
            f"Start-Process -FilePath {ps_literal(self.cfg.explorer_path)} "
            f"-ArgumentList {ps_literal(quoted_directory)}"
        )
        self.run_powershell(script)
