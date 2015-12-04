AM_CFLAGS = @CLEVIS_CFLAGS@ @LIBCRYPTO_CFLAGS@ @JANSSON_CFLAGS@
LDADD = libcore.a @LIBCRYPTO_LIBS@ @JANSSON_LIBS@
SUBDIRS = . pins

noinst_LIBRARIES = libcore.a
bin_PROGRAMS = clevis

libcore_a_SOURCES = \
	buf.c buf.h \
	mem.c mem.h \
	json.c json.h \
	pin.c pin.h \
	kdf.c kdf.h \
	ops.c ops.h \
	wrap.c wrap.h

