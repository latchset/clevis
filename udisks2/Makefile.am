AM_CFLAGS = @CLEVIS_CFLAGS@ @udisks2_CFLAGS@ -DCLEVIS_CMD_DIR=$(libexecdir)/$(PACKAGE_NAME)

EXTRA_DIST = clevis-luks-udisks2.desktop.in
CLEANFILES = clevis-luks-udisks2.desktop

autostartdir = $(sysconfdir)/xdg/autostart
autostart_DATA = clevis-luks-udisks2.desktop

libexec_PROGRAMS = clevis-luks-udisks2
clevis_luks_udisks2_LDADD = @luksmeta_LIBS@ @udisks2_LIBS@

%: %.in
	$(AM_V_GEN)$(SED) -e 's,@libexecdir\@,$(libexecdir),g' $(srcdir)/$@.in > $@
