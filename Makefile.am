DISTCHECK_CONFIGURE_FLAGS = \
    --with-systemdsystemunitdir=$$dc_install_base/$(systemdsystemunitdir)
if HAVE_DRACUT
DISTCHECK_CONFIGURE_FLAGS += \
    --with-dracutmodulesdir=$$dc_install_base/$(dracutmodulesdir)
endif

SUBDIRS = . src tests
EXTRA_DIST = COPYING

dist_man1_MANS = \
    doc/clevis-encrypt-tang.1 \
    doc/clevis-encrypt-http.1 \
    doc/clevis-encrypt-sss.1 \
    doc/clevis-luks-unlock.1 \
    doc/clevis-luks-bind.1 \
    doc/clevis-luks-unbind.1 \
    doc/clevis-decrypt.1 \
    doc/clevis.1

if HAVE_TPM2_TOOLS
    dist_man1_MANS += \
    doc/clevis-encrypt-tpm2.1
endif

dist_man7_MANS = \
    doc/clevis-luks-unlockers.7
