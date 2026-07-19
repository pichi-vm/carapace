#!/bin/bash
# SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

# dracut module: install carapace into a systemd initramfs so a
# `carapacehash=<root>` kernel command line assembles the root carapace into
# /dev/mapper/root before initrd-root-device.target. The carapace binary is
# multi-call: the same binary serves as the systemd generator (via the
# systemd-carapace-generator symlink) and as the unit's ExecStart
# (`carapace attach`). See carapace SPEC.md, "systemd Integration".

# Included only when the carapace binary is available on the host.
check() {
	require_binaries carapace || return 1
	return 0
}

# Needs systemd (the generator writes units) and dracut's dm plumbing
# (dm-mod load + /dev/mapper/control).
depends() {
	echo systemd dm
	return 0
}

# dm-verity + dm-snapshot back every scute; the carapace chain stacks them.
installkernel() {
	instmods dm-verity dm-snapshot dm-mod
}

install() {
	inst_multiple carapace

	# Register the multi-call binary as a systemd generator. dracut's ln_r
	# makes an initramfs-relative symlink, so it resolves regardless of the
	# initramfs mount point.
	local gendir="$systemdutildir/system-generators"
	[ -n "$systemdutildir" ] || gendir="/usr/lib/systemd/system-generators"
	mkdir -p "$initdir$gendir"
	ln_r "$(command -v carapace)" "$gendir/systemd-carapace-generator"
}
