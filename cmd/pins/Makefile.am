AM_CFLAGS = @CLEVIS_CFLAGS@ @jose_CFLAGS@ -DCLEVIS_CMD_DIR=$(libexecdir)/$(PACKAGE_NAME)
LDADD = @jose_LIBS@ libreadall.a

pindir = $(libexecdir)/$(PACKAGE_NAME)/pins

noinst_LIBRARIES = libreadall.a libhttp.a

libreadall_a_SOURCES = libreadall.c libreadall.h

libhttp_a_SOURCES = libhttp.c libhttp.h

pin_PROGRAMS = http sss tang

http_LDADD = $(LDADD) libhttp.a -lhttp_parser

sss_SOURCES = libsss.c libsss.h sss.c
sss_LDADD = $(LDADD) @libcrypto_LIBS@

tang_SOURCES = libtang.c libtang.h tang.c
tang_LDADD = $(LDADD) @libcrypto_LIBS@ libhttp.a -lhttp_parser

check_PROGRAMS = test
