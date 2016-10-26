AM_CFLAGS = @CLEVIS_CFLAGS@ @jose_CFLAGS@ @luksmeta_CFLAGS@ @udisks2_CFLAGS@

EXTRA_DIST = clevis-luks-udisks2.desktop.in
CLEANFILES = clevis-luks-udisks2.desktop

autostartdir = $(sysconfdir)/xdg/autostart
autostart_DATA = clevis-luks-udisks2.desktop

libexec_PROGRAMS = clevis-luks-udisks2
clevis_luks_udisks2_LDADD = @luksmeta_LIBS@ @udisks2_LIBS@

install-exec-hook:
	if [ -x $(DESTDIR)$(libexecdir)/clevis-luks-udisks2 ]; then \
	    chmod 4711 $(DESTDIR)$(libexecdir)/clevis-luks-udisks2; \
	fi

%: %.in
	$(AM_V_GEN)$(SED) \
		-e 's,@libexecdir\@,$(libexecdir),g' \
		$(srcdir)/$@.in > $@
