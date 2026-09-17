# SPDX-License-Identifier: GPL-2.0-only
obj-$(CONFIG_SECURITY_FORTRESS) := fortress.o

fortress-y := lsm.o policy.o policy_parse.o fs.o gate.o ipc.o netguard.o \
	       identity.o

# Stricter than the tree default, scoped to this directory only.
ccflags-y += -Wmissing-prototypes -Wmissing-declarations -Wold-style-definition
