AM_CFLAGS = @CLEVIS_CFLAGS@ @LIBCRYPTO_CFLAGS@ @JANSSON_CFLAGS@ @CURL_CFLAGS@

include_HEADERS = clevis.h

lib_LTLIBRARIES = libclevis.la
libclevis_la_LDFLAGS = -export-symbols-regex '^clevis_'
libclevis_la_LIBADD = @LIBCRYPTO_LIBS@ @JANSSON_LIBS@
libclevis_la_SOURCES = buf.c clevis.h

noinst_LTLIBRARIES = libcore.la
libcore_la_LIBADD = -ldl -lpthread libclevis.la
libcore_la_SOURCES = list.c list.h pin.c pin.h

bin_PROGRAMS = clevis
clevis_LDADD = libcore.la
clevis_SOURCES = clevis.c crypto.c crypto.h pwd.c pwd.h

pindir = @CLEVIS_PINDIR@
pin_LTLIBRARIES = pwd.la sss.la http.la

pwd_la_SOURCES = pin_pwd.c
pwd_la_LDFLAGS = -module -avoid-version
pwd_la_LIBADD = libclevis.la

sss_la_SOURCES = pin_sss_alg.c pin_sss_alg.h pin_sss.c
sss_la_LDFLAGS = -module -avoid-version
sss_la_LIBADD = libcore.la

http_la_SOURCES = pin_http.c
http_la_LDFLAGS = -module -avoid-version
http_la_LIBADD = libclevis.la @CURL_LIBS@
