#!/usr/bin/env python3

import argparse
import re
import sys

from packaging.version import Version

INIT_FILE = "udm_rest_client/__init__.py"
SETUP_FILE = "setup.py"
HISTORY_FILE = "HISTORY.rst"


def _validate_version(previous_version, current_version, filename):
    if Version(current_version) <= Version(previous_version):
        print(
            f"{filename}: Version in branch is equal or lower than released version:"
            f" {current_version} <= {previous_version}"
        )
        sys.exit(1)


def validate_version_before_release(previous_version):
    with open(INIT_FILE) as fin:
        text = fin.read()
        current_ini_version = re.search(r'__version__ = "([^\n\"].+)"', text).group(1)
    _validate_version(
        previous_version=previous_version, current_version=current_ini_version, filename=INIT_FILE
    )

    with open(SETUP_FILE) as fin:
        text = fin.read()
        current_setup_version = re.search(r'version="([^\n\"].+)"', text).group(1)
    _validate_version(
        previous_version=previous_version, current_version=current_setup_version, filename=SETUP_FILE
    )

    with open(HISTORY_FILE) as fin:
        text = fin.read()
        releases = re.findall(r"(\d+\.\d+\.\d+)\s\(\d{4}-\d{2}-\d{2}\)", text)
        if current_setup_version not in releases:
            print(
                f"{HISTORY_FILE} does not include an entry "
                f"for {current_setup_version} (listed versions: {releases})"
            )
            sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="release_validate_version",
        description="Validates that all current version is higher than released one.",
    )
    parser.add_argument("-p", "--previous_version", required=True)
    args = parser.parse_args()
    validate_version_before_release(args.previous_version)
