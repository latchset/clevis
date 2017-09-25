AM_CFLAGS = \
    @CLEVIS_CFLAGS@ \
    @jansson_CFLAGS@ \
    @libcrypto_CFLAGS@ \
    @jose_CFLAGS@ \
    @udisks2_CFLAGS@ \
    -D BINDIR='"@bindir@"' \
    -D CLEVIS_USER='"@CLEVIS_USER@"' \
    -D CLEVIS_GROUP='"@CLEVIS_GROUP@"'

dracutdir = @dracutmodulesdir@/60$(PACKAGE_NAME)
autostartdir = $(sysconfdir)/xdg/autostart

nodist_autostart_DATA = udisks2/clevis-luks-udisks2.desktop
dist_dracut_SCRIPTS = dracut/clevis-hook.sh dracut/module-setup.sh
libexec_PROGRAMS = udisks2/clevis-luks-udisks2

dist_check_SCRIPTS = \
    clevis-encrypt-test \
    clevis-decrypt-test

bin_PROGRAMS = \
    clevis-encrypt-sss \
    clevis-decrypt-sss

dist_bin_SCRIPTS = \
    clevis-encrypt-http \
    clevis-encrypt-tang \
    clevis-decrypt-http \
    clevis-decrypt-tang \
    clevis-bind-luks \
    clevis-luks-unlock \
    clevis-luks-bind \
    clevis-decrypt \
    clevis

clevis_encrypt_sss_SOURCES = clevis-encrypt-sss.c sss.c sss.h
clevis_decrypt_sss_SOURCES = clevis-decrypt-sss.c sss.c sss.h
udisks2_clevis_luks_udisks2_LDADD = @luksmeta_LIBS@ @udisks2_LIBS@
clevis_encrypt_sss_LDADD = @jose_LIBS@ @libcrypto_LIBS@
clevis_decrypt_sss_LDADD = @jose_LIBS@ @libcrypto_LIBS@

CLEANFILES=udisks2/clevis-luks-udisks2.desktop
EXTRA_DIST=udisks2/clevis-luks-udisks2.desktop.in

%: %.in
	$(AM_V_GEN)mkdir -p $(dir $@)
	$(AM_V_GEN)$(SED) \
		-e 's,@libexecdir\@,$(libexecdir),g' \
		$(srcdir)/$@.in > $@
