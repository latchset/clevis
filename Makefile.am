DISTCHECK_CONFIGURE_FLAGS = --with-dracutmodulesdir=$$dc_install_base/$(dracutmodulesdir)

ACLOCAL_AMFLAGS = -I m4
SUBDIRS = src dracut udisks2

EXTRA_DIST = COPYING tests/httpd.py
dist_check_SCRIPTS = tests/pin-test tests/pin-http tests/pin-sss tests/pin-tang
TESTS = $(dist_check_SCRIPTS)
