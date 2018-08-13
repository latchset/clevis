AM_CFLAGS = @CLEVIS_CFLAGS@

AM_TESTS_ENVIRONMENT = \
    SD_ACTIVATE="@SD_ACTIVATE@" \
    PATH=${top_srcdir}/src:${top_builddir}/src/:$(PATH)
TESTS = pin-test pin-sss pin-tang
dist_check_SCRIPTS = $(TESTS)
