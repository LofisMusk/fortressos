# SPDX-License-Identifier: GPL-2.0
# Host-side tests for the Fortress policy compiler and kernel parser.
#
#   make test        python unit tests + parser tests under ASan/UBSan
#   make fuzz        libFuzzer run (needs an LLVM clang with -fsanitize=fuzzer)

PYTHON   ?= python3
CC       ?= cc
FUZZ_CC  ?= clang
FUZZ_SECONDS ?= 60

ROOT     := ../..
KSRC     := $(ROOT)/kernel/security/fortress
PARSER   := $(KSRC)/policy_parse.c
OUT      := out

CFLAGS   := -std=c11 -O1 -g -Wall -Wextra -Wno-unused-parameter -Werror -I$(KSRC)
SAN      := -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer

.PHONY: test pytest hosttest fuzz clean

test: pytest hosttest

pytest:
	$(PYTHON) -m unittest -v test_fpol

$(OUT)/good.bin: $(ROOT)/tests/kernel/policy/good.json fpol.py
	@mkdir -p $(OUT)
	$(PYTHON) fpol.py compile $< -o $@

$(OUT)/host_test: host_test.c $(PARSER) $(KSRC)/policy_parse.h
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) $(SAN) -o $@ host_test.c $(PARSER)

hosttest: $(OUT)/host_test $(OUT)/good.bin
	$(OUT)/host_test $(OUT)/good.bin

$(OUT)/fuzz_parse: fuzz_parse.c $(PARSER) $(KSRC)/policy_parse.h
	@mkdir -p $(OUT)
	$(FUZZ_CC) $(CFLAGS) -fsanitize=fuzzer,address,undefined -o $@ fuzz_parse.c $(PARSER)

fuzz: $(OUT)/fuzz_parse $(OUT)/good.bin
	@mkdir -p $(OUT)/corpus
	cp $(OUT)/good.bin $(OUT)/corpus/
	$(OUT)/fuzz_parse -max_total_time=$(FUZZ_SECONDS) -max_len=8192 $(OUT)/corpus

clean:
	rm -rf $(OUT)
