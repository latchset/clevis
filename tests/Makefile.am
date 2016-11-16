AM_CFLAGS = @CLEVIS_CFLAGS@

dist_check_SCRIPTS = pin-test pin-http pin-sss pin-tang
check_PROGRAMS = pin-httpd

pin_httpd_LDFLAGS = -lhttp_parser

AM_TESTS_ENVIRONMENT = top_builddir='$(abs_top_builddir)' CLEVIS_CMD_DIR='$(abs_top_builddir)'/cmd
TESTS = $(dist_check_SCRIPTS)
