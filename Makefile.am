DISTCHECK_CONFIGURE_FLAGS = --with-dracutmodulesdir=$$dc_install_base/$(dracutmodulesdir)

ACLOCAL_AMFLAGS = -I m4
SUBDIRS = src dracut udisks2

EXTRA_DIST = COPYING
dist_check_SCRIPTS = tests/pin-test tests/pin-http tests/pin-sss tests/pin-tang
check_PROGRAMS = tests/httpd
TESTS = $(dist_check_SCRIPTS)

tests_httpd_LDFLAGS = -lhttp_parser
