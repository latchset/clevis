AM_CFLAGS = @CLEVIS_CFLAGS@ @jose_CFLAGS@
LDADD = @jose_LIBS@ libreadall.la

EXTRA_DIST = clevis.in clevis-decrypt.in clevis-encrypt.in clevis-bind-luks.in

bin_PROGRAMS = clevis clevis-encrypt clevis-decrypt clevis-pin clevis-pin-http clevis-pin-sss clevis-pin-tang
bin_SCRIPTS = clevis-bind-luks
noinst_LTLIBRARIES = libhttp.la libreadall.la
check_PROGRAMS = clevis-pin-test

libreadall_la_SOURCES = readall.c readall.h

libhttp_la_SOURCES = http.c http.h
libhttp_la_LIBADD = -lhttp_parser

clevis_pin_sss_SOURCES = clevis-pin-sss.c sss.c sss.h
clevis_pin_sss_LDADD = $(LDADD) @libcrypto_LIBS@

clevis_pin_http_LDADD = $(LDADD) libhttp.la

clevis_pin_tang_SOURCES = tang.c tang.h clevis-pin-tang.c
clevis_pin_tang_LDADD = $(LDADD) @libcrypto_LIBS@ libhttp.la
