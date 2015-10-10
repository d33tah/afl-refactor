#
# american fuzzy lop - makefile
# -----------------------------
#
# Written and maintained by Michal Zalewski <lcamtuf@google.com>
# 
# Copyright 2013, 2014, 2015 Google Inc. All rights reserved.
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
# 
#   http://www.apache.org/licenses/LICENSE-2.0
#

PROGNAME    = afl
VERSION     = 1.88b

PREFIX     ?= /usr/local
BIN_PATH    = $(PREFIX)/bin
HELPER_PATH = $(PREFIX)/lib/afl
DOC_PATH    = $(PREFIX)/share/doc/afl
MISC_PATH   = $(PREFIX)/share/afl

CFLAGS     ?= -O3 -funroll-loops
CFLAGS     += -Werror -Wall -D_FORTIFY_SOURCE=2 -g -Wno-pointer-sign \
	      -DAFL_PATH=\"$(HELPER_PATH)\" -DDOC_PATH=\"$(DOC_PATH)\" \
	      -DBIN_PATH=\"$(BIN_PATH)\" -DVERSION=\"$(VERSION)\"

AFL_FUZZ_OBJS = afl-fuzz.o fuzzing-engine.o util.o

ifneq "$(filter Linux GNU%,$(shell uname))" ""
  LDFLAGS  += -ldl
endif

COMM_HDR    = alloc-inl.h config.h debug.h types.h util.h

all: afl-fuzz

afl-fuzz: $(AFL_FUZZ_OBJS) $(COMM_HDR)
	$(CC) $(CFLAGS) $(AFL_FUZZ_OBJS) -o $@ $(LDFLAGS)

.NOTPARALLEL: clean

clean:
	rm -f afl-fuzz *.o *~ a.out core core.[1-9][0-9]* *.stackdump
