bin_PROGRAMS = statexfat
statexfat_SOURCES = src/statexfat.c \
                    src/exfat.c \
                    src/nls.c
man_MANS = statexfat.8

EXTRA_DIST = include
AM_CPPFLAGS = -I$(top_srcdir)/include

if DEBUG
AM_CPPFLAGS += -O0 -g3 -Wall -DSTATEXFAT_DEBUG
else
AM_CPPFLAGS += -O2
endif

statexfat.8: statexfat$(EXEEXT)
	help2man --no-discard-stderr --section=8 -N -o statexfat.8 ./statexfat
