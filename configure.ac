AC_PREREQ(2.59)
AC_INIT(clevis, 2)
AC_CANONICAL_SYSTEM
AC_PROG_CC_C99
AC_PROG_RANLIB
AC_PROG_SED

AM_INIT_AUTOMAKE([subdir-objects foreign no-dist-gzip dist-bzip2 parallel-tests])
AM_SILENT_RULES([yes])
AM_PROG_CC_C_O

PKG_PROG_PKG_CONFIG([0.25])

PKG_CHECK_MODULES([jose], [jose-openssl >= 6 jose-zlib >= 6])
PKG_CHECK_MODULES([luksmeta], [luksmeta >= 3])
PKG_CHECK_MODULES([libcrypto], [libcrypto])
PKG_CHECK_MODULES([udisks2], [udisks2])
PKG_CHECK_MODULES([dracut], [dracut])

AC_CHECK_HEADER([http_parser.h], [], [AC_MSG_ERROR([http-parser required!])])
AC_SEARCH_LIBS([http_parser_execute], [http_parser], [], [AC_MSG_ERROR([http-parser required!])])

AC_ARG_WITH([dracutmodulesdir],
	    [AS_HELP_STRING([--with-dracutmodulesdir=DIR], [Directory for dracut modules])],
	    [],
	    [with_dracutmodulesdir=$($PKG_CONFIG --variable=dracutmodulesdir dracut)])
AC_SUBST([dracutmodulesdir], [$with_dracutmodulesdir])

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

AC_CONFIG_FILES([Makefile cmd/Makefile cmd/pins/Makefile dracut/Makefile udisks2/Makefile tests/Makefile])
AC_OUTPUT
