AM_CFLAGS = \
    @CLEVIS_CFLAGS@ \
    @jansson_CFLAGS@ \
    @libcrypto_CFLAGS@ \
    @jose_CFLAGS@ \
    @udisks2_CFLAGS@ \
    @audit_CFLAGS@ \
    -D BINDIR='"@bindir@"' \
    -D CLEVIS_USER='"@CLEVIS_USER@"' \
    -D CLEVIS_GROUP='"@CLEVIS_GROUP@"'

autostartdir = $(sysconfdir)/xdg/autostart

nodist_autostart_DATA = clevis-luks-udisks2.desktop
libexec_PROGRAMS = clevis-luks-udisks2

clevis_luks_udisks2_LDADD = @luksmeta_LIBS@ @udisks2_LIBS@ @audit_LIBS@

CLEANFILES=clevis-luks-udisks2.desktop
EXTRA_DIST=clevis-luks-udisks2.desktop.in

%: %.in
	$(AM_V_GEN)mkdir -p $(dir $@)
	$(AM_V_GEN)$(SED) \
		-e 's,@libexecdir\@,$(libexecdir),g' \
		$(srcdir)/$@.in > $@

install-exec-hook:
	chmod u+s $(DESTDIR)$(libexecdir)/clevis-luks-udisks2
