"""Command construction tests for the VMware controller (vmrun is never run)."""

import base64
import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest

from sentinelcap.config import VMwareConfig
from sentinelcap.errors import SentinelcapError
from sentinelcap.vm import VMwareController, VMwareError

VMX = r"D:\VMs\Victim\Victim.vmx"


def _config() -> VMwareConfig:
    return VMwareConfig(vmx_path=VMX, guest_user="Administrator", guest_password="test-password")


def _done(stdout: str = "", code: int = 0) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=code, stdout=stdout, stderr="")


def _script(run_guest: Mock) -> str:
    """The PowerShell script of the last runProgramInGuest call."""
    args = run_guest.call_args.args[0]
    assert args[:2] == ["runProgramInGuest", VMX]
    assert "-EncodedCommand" in args
    return base64.b64decode(args[-1]).decode("utf-16-le")


@pytest.mark.parametrize(
    "directory", [r"C:\Users\Public\Documents", r"C:\Users\sysmaint\3D Objects"]
)
def test_open_explorer_passes_the_directory_as_one_argument(directory: str) -> None:
    controller = VMwareController(_config())
    controller._run_guest = Mock(return_value=_done())  # type: ignore[method-assign]
    controller.open_explorer(directory)
    assert _script(controller._run_guest) == (
        rf"""Start-Process -FilePath 'C:\Windows\explorer.exe' -ArgumentList '"{directory}"'"""
    )


def test_snapshot_commands_and_revert_snapshot_uses_baseline() -> None:
    controller = VMwareController(_config())
    controller._run = Mock(return_value=_done())  # type: ignore[method-assign]
    controller.revert_to_baseline()
    controller.revert_to("original")
    controller.create_snapshot("baseline")
    assert [c.args[0] for c in controller._run.call_args_list] == [
        ["revertToSnapshot", VMX, "baseline"],
        ["revertToSnapshot", VMX, "original"],
        ["snapshot", VMX, "baseline"],
    ]


def test_list_snapshots_skips_total_line() -> None:
    controller = VMwareController(_config())
    controller._run = Mock(return_value=_done("Total snapshots: 2\noriginal\nbaseline\n"))  # type: ignore[method-assign]
    assert controller.list_snapshots() == ["original", "baseline"]


def test_delete_snapshot_ignores_missing_but_raises_if_still_present() -> None:
    controller = VMwareController(_config())
    controller._run = Mock(side_effect=[_done(code=255), _done("Total snapshots: 1\noriginal\n")])  # type: ignore[method-assign]
    controller.delete_snapshot("baseline")  # did not exist: fine
    assert controller._run.call_args_list[0].args[0] == ["deleteSnapshot", VMX, "baseline"]

    controller._run = Mock(
        side_effect=[_done(code=255), _done("Total snapshots: 2\noriginal\nbaseline\n")]
    )  # type: ignore[method-assign]
    with pytest.raises(VMwareError, match="still exists"):
        controller.delete_snapshot("baseline")


def test_guest_file_operations_use_credentials() -> None:
    controller = VMwareController(_config())
    controller._run = Mock(return_value=_done())  # type: ignore[method-assign]
    controller.copy_to_guest(Path("a.zip"), r"C:\Windows\Temp\a.zip")
    controller.delete_file_in_guest(r"C:\Windows\Temp\a.zip")
    creds = ["-gu", "Administrator", "-gp", "test-password"]
    assert controller._run.call_args_list[0].args[0] == [
        *creds,
        "copyFileFromHostToGuest",
        VMX,
        "a.zip",
        r"C:\Windows\Temp\a.zip",
    ]
    assert controller._run.call_args_list[1].args[0] == [
        *creds,
        "deleteFileInGuest",
        VMX,
        r"C:\Windows\Temp\a.zip",
    ]


def test_file_exists_and_rename_in_guest() -> None:
    controller = VMwareController(_config())
    creds = ["-gu", "Administrator", "-gp", "test-password"]
    controller._run = Mock(
        side_effect=[  # type: ignore[method-assign]
            _done("The file exists."),
            _done("The file does not exist.", 255),
            _done("The file does not exist."),
            _done(),
        ]
    )
    assert controller.file_exists_in_guest(r"C:\a b\x.exe") is True
    assert controller.file_exists_in_guest(r"C:\x.exe") is False
    assert controller.file_exists_in_guest(r"C:\x.exe") is False
    controller.rename_file_in_guest(r"C:\a b\x.exe", r"C:\a b\y.exe")
    assert controller._run.call_args_list[0].args[0] == [
        *creds,
        "fileExistsInGuest",
        VMX,
        r"C:\a b\x.exe",
    ]
    assert controller._run.call_args_list[3].args[0] == [
        *creds,
        "renameFileInGuest",
        VMX,
        r"C:\a b\x.exe",
        r"C:\a b\y.exe",
    ]


def test_run_in_guest_waits_and_refuses_arguments_with_spaces() -> None:
    controller = VMwareController(_config())
    controller._run_guest = Mock(return_value=_done())  # type: ignore[method-assign]
    controller.run_in_guest(r"C:\Program Files\7-Zip\7z.exe", "x", "-y")
    controller._run_guest.assert_called_once_with(
        ["runProgramInGuest", VMX, "-interactive", r"C:\Program Files\7-Zip\7z.exe", "x", "-y"]
    )
    with pytest.raises(ValueError, match="whitespace"):
        controller.run_in_guest("7z.exe", r"-oC:\Users\x\Saved Games")


def test_vmware_error_is_a_sentinelcap_error() -> None:
    assert issubclass(VMwareError, SentinelcapError)


def test_list_dirs_in_guest_reads_back_listing() -> None:
    controller = VMwareController(_config())
    controller._run_guest = Mock(return_value=_done())  # type: ignore[method-assign]

    def fake_copy(guest_path: str, host_path) -> None:
        Path(host_path).write_text(
            "\ufeffC:\\Users\\Public\\Documents\r\nC:\\Users\\sysmaint\\Saved Games\r\n",
            encoding="utf-8",
        )

    controller.copy_from_guest = Mock(side_effect=fake_copy)  # type: ignore[method-assign]
    controller.delete_file_in_guest = Mock()  # type: ignore[method-assign]
    dirs = controller.list_dirs_in_guest([r"C:\Users\Public", r"C:\Users\sysmaint"])
    assert dirs == [r"C:\Users\Public\Documents", r"C:\Users\sysmaint\Saved Games"]

    script = _script(controller._run_guest)
    assert "'C:\\Users\\Public','C:\\Users\\sysmaint'" in script and "-Directory -Recurse" in script
    controller.delete_file_in_guest.assert_called_once()
