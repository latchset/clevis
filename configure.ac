AC_PREREQ(2.59)
AC_INIT(clevis, 9)
AC_CANONICAL_SYSTEM
AC_PROG_CC_C99
AC_PROG_RANLIB
AC_PROG_SED

AM_INIT_AUTOMAKE([subdir-objects foreign no-dist-gzip dist-bzip2 parallel-tests])
AM_SILENT_RULES([yes])
AM_PROG_CC_C_O

PKG_PROG_PKG_CONFIG([0.25])

PKG_CHECK_MODULES([luksmeta], [luksmeta >= 8])
PKG_CHECK_MODULES([libcrypto], [libcrypto])
PKG_CHECK_MODULES([jansson], [jansson >= 2.10])
PKG_CHECK_MODULES([udisks2], [udisks2])
PKG_CHECK_MODULES([jose], [jose >= 8])
PKG_CHECK_MODULES([systemd], [systemd])
PKG_CHECK_MODULES([audit], [audit >= 2.7.8])

AC_DEFUN([AC_PROG_DRACUT], [AC_CHECK_PROG([DRACUT], [dracut], [yes])])
AC_DEFUN([AC_PROG_INITRAMFS_TOOLS], [AC_CHECK_PROG([INITRAMFS_TOOLS], [update-initramfs], [yes])])

AC_PROG_DRACUT
if test x"${DRACUT}" == x"yes" ; then
    AC_ARG_WITH([dracutmodulesdir],
            [AS_HELP_STRING([--with-dracutmodulesdir=DIR], [Directory for dracut modules])],
            [],
            [with_dracutmodulesdir=$($PKG_CONFIG --variable=dracutmodulesdir dracut)])
    AC_SUBST([dracutmodulesdir], [$with_dracutmodulesdir])
fi

AC_PROG_INITRAMFS_TOOLS
if test x"${INITRAMFS_TOOLS}" == x"yes" ; then
    AC_ARG_WITH([initramfstoolsmodulesdir],
            [AS_HELP_STRING([--with-initramfstoolsmodulesdir=DIR], [Directory for initramfs-tools modules])],
            [],
            [with_initramfstoolsmodulesdir=$initramfstoolsmodulesdir])
    AC_SUBST([initramfstoolsmodulesdir], [$with_initramfstoolsmodulesdir])
fi

if test -z "${INITRAMFS_TOOLS}" && test -z "${DRACUT}" ; then
    AC_MSG_ERROR([Please install dracut or initramfs-tools.])
fi

AC_CHECK_PROG([PWMAKE], [pwmake], [yes])
test -n "$PWMAKE" || AC_MSG_ERROR([pwmake required!])

AC_ARG_WITH([systemdsystemunitdir],
            [AS_HELP_STRING([--with-systemdsystemunitdir=DIR], [Directory for systemd unit files])],
            [],
            [with_systemdsystemunitdir=$($PKG_CONFIG --variable=systemdsystemunitdir systemd)])

AC_SUBST([systemdsystemunitdir], [$with_systemdsystemunitdir])

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

for ac_prog in createprimary pcrlist createpolicy create load unseal; do
    unset TPM2_TOOLS
    unset ac_cv_prog_TPM2_TOOLS
    AC_CHECK_PROG([TPM2_TOOLS], [tpm2_$ac_prog], [yes])
    test -z "$TPM2_TOOLS" && break
done

test -n "$TPM2_TOOLS" || AC_MSG_WARN([tpm2_$ac_prog not found, tpm2 pin won't be installed])

AM_CONDITIONAL([HAVE_TPM2_TOOLS], [test -n "$TPM2_TOOLS"])

AC_ARG_ENABLE([user],
              AS_HELP_STRING([--enable-user=USER],
                             [Set unprivileged user (default: root)]),
              [CLEVIS_USER="${enableval}"],
              [CLEVIS_USER="root"])
AC_ARG_ENABLE([group],
              AS_HELP_STRING([--enable-group=GROUP],
                             [Set unprivileged group (default: root)]),
              [CLEVIS_GROUP="${enableval}"],
              [CLEVIS_GROUP="root"])
AC_SUBST([CLEVIS_USER])
AC_SUBST([CLEVIS_GROUP])

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
    src/systemd/Makefile
    src/udisks2/Makefile
    src/dracut/Makefile
    src/initramfs-tools/Makefile
    tests/Makefile
    src/Makefile
    Makefile
])
AC_OUTPUT
