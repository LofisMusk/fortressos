#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# Wire the Fortress LSM into a Linux 5.4 kernel tree (Samsung sm7325 or
# vanilla). Idempotent: safe to run again on an already integrated tree.
#
#   kernel/integrate.sh <kernel-tree>
#
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
tree="${1:?usage: $0 <kernel-tree>}"

[ -f "$tree/security/Kconfig" ] && [ -f "$tree/security/Makefile" ] ||
	{ echo "integrate: $tree does not look like a kernel tree" >&2; exit 1; }

rm -rf "$tree/security/fortress"
cp -R "$here/security/fortress" "$tree/security/fortress"

# Kconfig: source ours right after SafeSetID (present in every 5.4 tree).
if ! grep -q 'security/fortress/Kconfig' "$tree/security/Kconfig"; then
	awk '{ print }
	     /^source "security\/safesetid\/Kconfig"/ {
		print "source \"security/fortress/Kconfig\""; done = 1 }
	     END { if (!done) exit 1 }' \
		"$tree/security/Kconfig" > "$tree/security/Kconfig.fortress" ||
		{ echo "integrate: anchor not found in security/Kconfig" >&2; exit 1; }
	cat "$tree/security/Kconfig.fortress" > "$tree/security/Kconfig"
	rm "$tree/security/Kconfig.fortress"
fi

if ! grep -q 'CONFIG_SECURITY_FORTRESS' "$tree/security/Makefile"; then
	cat >> "$tree/security/Makefile" <<'EOF'

# Fortress OS guard
subdir-$(CONFIG_SECURITY_FORTRESS)	+= fortress
obj-$(CONFIG_SECURITY_FORTRESS)		+= fortress/
EOF
fi

echo "integrate: fortress wired into $tree"
