AC_PREREQ(2.59)
AC_INIT(clevis, 1)
AC_CONFIG_MACRO_DIRS([m4])
AC_CANONICAL_SYSTEM
AC_PROG_CC_C99

AM_INIT_AUTOMAKE([subdir-objects foreign no-dist-gzip dist-bzip2 parallel-tests])
AM_SILENT_RULES([yes])
AM_PROG_CC_C_O

LT_INIT([disable-static])

PKG_PROG_PKG_CONFIG([0.25])

PKG_CHECK_MODULES([LIBCRYPTO], [libcrypto])
PKG_CHECK_MODULES([JANSSON], [jansson])

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

AC_SUBST([CLEVIS_PINDIR], [${libdir}/${PACKAGE_NAME}])
AX_DEFINE_DIR(CLEVIS_PINDIR, CLEVIS_PINDIR, [Location of pins (plugins)])

AC_CONFIG_FILES([clevis.pc Makefile src/Makefile src/pins/Makefile])
AC_OUTPUT
