AM_CFLAGS = @CLEVIS_CFLAGS@ @jose_CFLAGS@ @luksmeta_CFLAGS@ @udisks2_CFLAGS@ -DCLEVIS_CMD_DIR=$(libexecdir)/$(PACKAGE_NAME)
SUBDIRS = . pins

clevisdir = $(libexecdir)/$(PACKAGE_NAME)
clevis_PROGRAMS = encrypt decrypt
dist_clevis_SCRIPTS = bind-luks

decrypt_LDADD = $(LDADD) @jose_LIBS@
