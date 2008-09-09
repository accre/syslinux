## -----------------------------------------------------------------------
##
##   Copyright 2001-2008 H. Peter Anvin - All Rights Reserved
##
##   This program is free software; you can redistribute it and/or modify
##   it under the terms of the GNU General Public License as published by
##   the Free Software Foundation, Inc., 51 Franklin St, Fifth Floor,
##   Boston MA 02110-1301, USA; either version 2 of the License, or
##   (at your option) any later version; incorporated herein by reference.
##
## -----------------------------------------------------------------------

##
## GDB remote debugging
##

topdir = ../..
include ../MCONFIG

CFLAGS += -fPIE

LIBS	   = ../libutil/libutil_com.a ../lib/libcom32.a $(LIBGCC)
LNXLIBS	   = ../libutil/libutil_lnx.a

MODULES	  = gdbstub.c32
TESTFILES =

OBJS = main.o int.o serial.o gdbstub.o

all: $(MODULES) $(TESTFILES)

gdbstub.elf : $(OBJS) $(LIBS) $(C_LIBS)
	$(LD) $(LDFLAGS) -o $@ $^

tidy dist:
	rm -f *.o *.lo *.a *.lst *.elf .*.d *.tmp

clean: tidy
	rm -f *.lss *.c32 *.lnx *.com

spotless: clean
	rm -f *~ \#*

install: all
	mkdir -m 755 -p $(INSTALLROOT)$(AUXDIR)
	install -m 644 $(MODULES) $(INSTALLROOT)$(AUXDIR)

-include .*.d