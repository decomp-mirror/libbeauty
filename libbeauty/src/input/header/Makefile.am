include $(top_srcdir)/misc/Makefile.common

#AM_CXXFLAGS = -O0 -g3 -Wall -I/usr/local/include/llvm -L/usr/local/lib/ -std=c++11
#AM_CFLAGS = -O0 -g3 -Wall
#CFLAGS = -O0 -g3 -Wall

#modulesdir = $(pkglibdir)/beauty_exe
lib_LTLIBRARIES = libbeauty_input_header.la
#bin_PROGRAMS = dis

#include_HEADERS = \
#	exe.h

#noinst_HEADERS = \
#	exe.h

libbeauty_input_header_la_SOURCES = \
	find_types.cpp
libbeauty_input_header_la_LIBADD = -L/usr/lib/llvm-5.0/lib -lLLVM-5.0
libbeauty_input_header_la_LDFLAGS = \
	 -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)
