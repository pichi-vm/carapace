#!/usr/bin/env bash
# SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

# CI gate: carapace contains NO `unsafe` — all of it lives in the devmap /
# lodown substrate crates. The crate root already sets
# `#![forbid(unsafe_code)]`; this grep is defense-in-depth against a future
# contributor flipping that attribute. Comment-only lines are exempt (module
# docstrings discuss `unsafe`).
set -euo pipefail

cd "$(dirname "$0")/.."

if command -v rg >/dev/null 2>&1; then
    matches=$(rg --line-number --type rust '\bunsafe\b' src/ \
        | grep -vE ':\s*//' \
        | grep -vE '\s*//.*\bunsafe\b' \
        || true)
else
    matches=$(grep -RnE '\bunsafe\b' src/ \
        | grep -vE ':\s*//' \
        | grep -vE '\s*//.*\bunsafe\b' \
        || true)
fi

if [ -n "$matches" ]; then
    echo "FAIL: unsafe keyword found in carapace src/ (all unsafe belongs in devmap/lodown):" >&2
    echo "$matches" >&2
    exit 1
fi

echo "OK: carapace src/ is unsafe-free"
