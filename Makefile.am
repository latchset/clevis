DISTCHECK_CONFIGURE_FLAGS = --with-dracutmodulesdir=$$dc_install_base/$(dracutmodulesdir)
SUBDIRS = . cmd dracut udisks2 tests

AM_CFLAGS = @CLEVIS_CFLAGS@ -DCLEVIS_CMD_DIR=$(libexecdir)/$(PACKAGE_NAME)

EXTRA_DIST = COPYING

bin_PROGRAMS = clevis
