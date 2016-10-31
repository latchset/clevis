DISTCHECK_CONFIGURE_FLAGS = --with-dracutmodulesdir=$$dc_install_base/$(dracutmodulesdir)

AM_CFLAGS = @CLEVIS_CFLAGS@ @jose_CFLAGS@ @luksmeta_CFLAGS@ @udisks2_CFLAGS@

EXTRA_DIST = COPYING
CLEANFILES =

##
### Main
##

noinst_LIBRARIES = libhttp.a libreadall.a
bin_PROGRAMS = clevis clevis-encrypt clevis-decrypt clevis-pin-http clevis-pin-sss clevis-pin-tang
dist_bin_SCRIPTS = clevis-bind-luks

libreadall_a_SOURCES = readall.c readall.h

libhttp_a_SOURCES = http.c http.h

clevis_decrypt_LDADD = $(LDADD) @jose_LIBS@

clevis_pin_http_LDADD = $(LDADD) @jose_LIBS@ libreadall.a libhttp.a -lhttp_parser

clevis_pin_sss_SOURCES = clevis-pin-sss.c sss.c sss.h
clevis_pin_sss_LDADD = $(LDADD) @jose_LIBS@ @libcrypto_LIBS@ libreadall.a

clevis_pin_tang_SOURCES = tang.c tang.h clevis-pin-tang.c
clevis_pin_tang_LDADD = $(LDADD) @jose_LIBS@ @libcrypto_LIBS@ libreadall.a libhttp.a -lhttp_parser

##
### Tests
##

dist_check_SCRIPTS = test-pin-test test-pin-http test-pin-sss test-pin-tang
check_PROGRAMS = clevis-pin-test test-pin-httpd
TESTS = $(dist_check_SCRIPTS)

clevis_pin_test_LDADD = @jose_LIBS@ libreadall.a
test_pin_httpd_LDFLAGS = -lhttp_parser

##
### Dracut
##

dracutdir = @dracutmodulesdir@/60$(PACKAGE_NAME)
dist_dracut_SCRIPTS = module-setup.sh clevis-hook.sh

##
### UDisks2
##

EXTRA_DIST += clevis-luks-udisks2.desktop.in
CLEANFILES += clevis-luks-udisks2.desktop

autostartdir = $(sysconfdir)/xdg/autostart
autostart_DATA = clevis-luks-udisks2.desktop

libexec_PROGRAMS = clevis-luks-udisks2
clevis_luks_udisks2_LDADD = @luksmeta_LIBS@ @udisks2_LIBS@

%: %.in
	$(AM_V_GEN)$(SED) -e 's,@libexecdir\@,$(libexecdir),g' $(srcdir)/$@.in > $@
