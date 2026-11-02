#!/usr/bin/env python3
# SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Run root tests with private fixtures and reject any attached fixture loops."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time


class TestRun:
    def __init__(self, directory):
        self.directory = directory

    def attached_loops(self):
        result = subprocess.run(
            ["losetup", "--list", "--json", "--output", "NAME,BACK-FILE"],
            capture_output=True, text=True, check=True,
        )
        prefix = str(self.directory) + "/"
        return [
            device for device in json.loads(result.stdout).get("loopdevices", [])
            if (device.get("back-file") or "").startswith(prefix)
        ]

    def run(self, command):
        env = dict(os.environ, TMPDIR=str(self.directory))
        try:
            return subprocess.run(command, env=env, check=False).returncode
        finally:
            # Deferred dm removal and loop autoclear may finish asynchronously.
            deadline = time.monotonic() + 5
            while True:
                attached = self.attached_loops()
                if not attached or time.monotonic() >= deadline:
                    break
                time.sleep(0.02)
            print("Attached test fixture loops after tests: " + str(len(attached)), flush=True)
            if attached:
                raise RuntimeError("Test fixture loops leaked: " + json.dumps(attached))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit("usage: check-test-loops.py COMMAND [ARG ...]")
    # Resolve the path so it matches losetup even if TMPDIR contains symlinks.
    with tempfile.TemporaryDirectory(prefix="carapace-tests-") as temporary:
        raise SystemExit(TestRun(Path(temporary).resolve()).run(sys.argv[1:]))
