AC_PREREQ(2.59)
AC_INIT(clevis, 5)
AC_CANONICAL_SYSTEM
AC_PROG_CC_C99
AC_PROG_RANLIB
AC_PROG_SED

AM_INIT_AUTOMAKE([subdir-objects foreign no-dist-gzip dist-bzip2 parallel-tests])
AM_SILENT_RULES([yes])
AM_PROG_CC_C_O

PKG_PROG_PKG_CONFIG([0.25])

PKG_CHECK_MODULES([luksmeta], [luksmeta >= 3])
PKG_CHECK_MODULES([libcrypto], [libcrypto])
PKG_CHECK_MODULES([jansson], [jansson])
PKG_CHECK_MODULES([udisks2], [udisks2])
PKG_CHECK_MODULES([jose], [jose >= 8])
PKG_CHECK_MODULES([dracut], [dracut])

AC_ARG_WITH([dracutmodulesdir],
	    [AS_HELP_STRING([--with-dracutmodulesdir=DIR], [Directory for dracut modules])],
	    [],
	    [with_dracutmodulesdir=$($PKG_CONFIG --variable=dracutmodulesdir dracut)])
AC_SUBST([dracutmodulesdir], [$with_dracutmodulesdir])

for ac_prog in systemd-socket-activate systemd-activate; do
    AC_CHECK_PROG([SD_ACTIVATE], [$ac_prog], [$as_dir/$ac_prog], [],
		  [$PATH$PATH_SEPARATOR$($PKG_CONFIG --variable=systemdutildir systemd)])
    test -n "$SD_ACTIVATE" && break
done

test -n "$SD_ACTIVATE" || AC_MSG_ERROR([systemd-socket-activate required!])

AC_MSG_CHECKING([systemd-socket-activate inetd flag])
if $SD_ACTIVATE --help | grep -q inetd; then
    SD_ACTIVATE="$SD_ACTIVATE --inetd"
    AC_MSG_RESULT([--inetd])
else
    AC_MSG_RESULT([(default)])
fi

AC_SUBST(SD_ACTIVATE)

CLEVIS_CFLAGS="\
-Wall \
-Wextra \
-Werror \
-Wstrict-aliasing \
-Wchar-subscripts \
-Wformat-security \
-Wmissing-declarations \
-Wmissing-prototypes \
-Wnested-externs \
-Wpointer-arith \
-Wshadow \
-Wsign-compare \
-Wstrict-prototypes \
-Wtype-limits \
-Wno-missing-field-initializers \
-Wno-unused-parameter \
"
AC_SUBST([CLEVIS_CFLAGS])

AC_CONFIG_FILES([
    tests/Makefile
    src/Makefile
    Makefile
])
AC_OUTPUT
