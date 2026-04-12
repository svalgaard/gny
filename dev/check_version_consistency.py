#!/usr/bin/env python3
"""Check that version numbers are consistent across project files."""

import argparse
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent


def get_changelog_version():
    text = (ROOT / "debian" / "changelog").read_text()
    # First line: "gny (UPSTREAM-DEBREV) ..."
    m = re.match(r"^\S+\s+\(([^)]+)\)", text)
    if not m:
        sys.exit("ERROR: could not parse version from debian/changelog")
    full = m.group(1)

    m2 = re.match(r"^((\d+\.\d+\.\d+)-\d+)$", full)
    if not m2:
        sys.exit(
            f"ERROR: debian/changelog version {full!r} does "
            "not match expected format x.y.z-d"
        )
    upstream = m2.group(2)
    return upstream, full


def get_pyproject_version():
    text = (ROOT / "pyproject.toml").read_text()
    m = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    if not m:
        sys.exit("ERROR: could not find version in pyproject.toml")
    return m.group(1)


def get_init_version():
    text = (ROOT / "gny" / "__init__.py").read_text()
    m = re.search(r'^__version__\s*=\s*"([^"]+)"', text, re.MULTILINE)
    if not m:
        sys.exit("ERROR: could not find __version__ in gny/__init__.py")
    return m.group(1)


def fix_pyproject_version(new_version):
    path = ROOT / "pyproject.toml"
    text = path.read_text()
    new_text = re.sub(
        r'^(version\s*=\s*)"[^"]+"',
        rf'\1"{new_version}"',
        text,
        flags=re.MULTILINE,
    )
    path.write_text(new_text)
    print(f"Fixed pyproject.toml: version = {new_version!r}")


def fix_init_version(new_version):
    path = ROOT / "gny" / "__init__.py"
    text = path.read_text()
    new_text = re.sub(
        r'^(__version__\s*=\s*)"[^"]+"',
        rf'\1"{new_version}"',
        text,
        flags=re.MULTILINE,
    )
    path.write_text(new_text)
    print(f"Fixed gny/__init__.py: __version__ = {new_version!r}")


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
    )
    parser.add_argument(
        "-s",
        action="store_true",
        help="Print suggested git commands when versions are consistent",
    )
    parser.add_argument(
        "--fix",
        action="store_true",
        help="Apply the debian/changelog upstream version to pyproject.toml "
        "and gny/__init__.py",
    )
    args = parser.parse_args()

    changelog_upstream, changelog_full = get_changelog_version()
    pyproject = get_pyproject_version()
    init = get_init_version()

    if args.fix:
        if pyproject != changelog_upstream:
            fix_pyproject_version(changelog_upstream)
        if init != changelog_upstream:
            fix_init_version(changelog_upstream)
        return

    ok = True
    if pyproject != init:
        print(
            f"MISMATCH: pyproject.toml has {pyproject!r} but __init__.py has {init!r}"
        )
        ok = False
    if pyproject != changelog_upstream:
        print(
            f"MISMATCH: pyproject.toml has {pyproject!r} "
            f"but debian/changelog has {changelog_full!r} "
            f"(upstream part: {changelog_upstream!r})"
        )
        ok = False

    if ok:
        print(f"OK: all versions consistent ({pyproject})")

        if args.s:
            print("git pull && git push")
            print("# Check that this looks as expected. Check CI/CD flow for errors.")
            print("git status")
            print("git diff")
            print(f'git commit -am "Release version {pyproject}"')
            print(f"git tag v{pyproject} && git push origin v{pyproject} && git push")
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
