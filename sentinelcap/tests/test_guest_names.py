"""Sample names and guest target directories."""

from __future__ import annotations

import random

import pytest

from sentinelcap import guest_names


@pytest.mark.parametrize(
    "name",
    [
        "setup.exe",
        "MySetup_1.exe",
        "x_SETUP.exe",
        *guest_names.FORBIDDEN_SUFFIXES,
        "MyOneDrive.exe",
    ],
)
def test_forbidden_names_are_rejected(name: str) -> None:
    with pytest.raises(ValueError):
        guest_names.assert_safe_name(name)


def test_generated_names_are_safe_and_business_like() -> None:
    rng = random.Random(1)
    for _ in range(500):
        name = guest_names.random_name(rng)
        assert guest_names.assert_safe_name(name) == name
        base, rest = name.split("_")
        assert (
            base in guest_names.BASE_NAMES
            and len(rest) == len("a7f3.exe")
            and rest.endswith(".exe")
        )
        assert name.count(".") == 1  # no double extension


def test_random_name_is_reproducible_with_seed() -> None:
    a = [guest_names.random_name(random.Random(7)) for _ in range(3)]
    b = [guest_names.random_name(random.Random(7)) for _ in range(3)]
    assert a == b


def test_spread_over_roots_is_even_and_seeded() -> None:
    roots = ["A", "B", "C", "D", "E"]
    a = guest_names.spread_over_roots(37, roots, random.Random(9))
    assert a == guest_names.spread_over_roots(37, roots, random.Random(9))
    counts = [a.count(r) for r in roots]
    assert sum(counts) == 37
    assert max(counts) - min(counts) <= 1


def test_group_by_root() -> None:
    dirs = [r"C:\Users\Public\Music", r"D:\Backup\2024", r"C:\Users\PublicX\a"]
    assert guest_names.group_by_root(dirs, [r"C:\Users\Public", r"D:\Backup", r"D:\Shares"]) == {
        r"C:\Users\Public": [r"C:\Users\Public\Music"],
        r"D:\Backup": [r"D:\Backup\2024"],
        r"D:\Shares": [],
    }


def test_target_dirs_keep_only_safe_dirs_under_roots_sorted() -> None:
    roots = [r"C:\Users\Public", r"D:\Shares"]
    listing = [
        r"D:\Shares\Finance",
        r"C:\Users\Public\Documents",
        r"C:\Users\Public",  # the root itself is not a sub-directory
        r"C:\Users\PublicX\Docs",  # prefix but not under the root
        r"C:\Windows\Temp",
        r"D:\Shares\Setup Files\x",  # contains "setup"
        r"c:\users\public\documents",  # duplicate, other case
        "",
    ]
    assert guest_names.usable_target_dirs(listing, roots) == [
        r"C:\Users\Public\Documents",
        r"D:\Shares\Finance",
    ]
    assert guest_names.usable_target_dirs(
        list(reversed(listing)), roots
    ) == guest_names.usable_target_dirs(listing, roots)
