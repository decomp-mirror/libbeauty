include $(top_srcdir)/misc/Makefile.common

#AM_CXXFLAGS = -O0 -g3 -Wall -I/usr/local/include/llvm -L/usr/local/lib/ -std=c++11
#AM_CFLAGS = -O0 -g3 -Wall
#CFLAGS = -O0 -g3 -Wall

#modulesdir = $(pkglibdir)/beauty_exe
lib_LTLIBRARIES = libbeauty_output_llvm.la
#bin_PROGRAMS = dis

#include_HEADERS = \
#	exe.h

#noinst_HEADERS = \
#	exe.h

libbeauty_output_llvm_la_SOURCES = \
	llvm_ir.cpp mytool.cpp
libbeauty_output_llvm_la_LIBADD = -L/usr/lib/llvm-6.0/lib -lLLVM-6.0
libbeauty_output_llvm_la_LDFLAGS = \
	 -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)
