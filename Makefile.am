DISTCHECK_CONFIGURE_FLAGS = \
    --with-systemdsystemunitdir=$$dc_install_base/$(systemdsystemunitdir) \
    --with-dracutmodulesdir=$$dc_install_base/$(dracutmodulesdir)

SUBDIRS = . src tests
EXTRA_DIST = COPYING
BUILT_SOURCES=
CLEANFILES=

man_ADOC_FILES = \
    doc/clevis.1.adoc \
    doc/clevis-decrypt.1.adoc \
    doc/clevis-encrypt-sss.1.adoc \
    doc/clevis-encrypt-tang.1.adoc \
    doc/clevis-encrypt-tpm2.1.adoc \
    doc/clevis-luks-bind.1.adoc \
    doc/clevis-luks-unbind.1.adoc \
    doc/clevis-luks-unlock.1.adoc \
    doc/clevis-luks-unlockers.7.adoc

EXTRA_DIST += $(man_ADOC_FILES)

if HAVE_A2X
man_ROFF_FILES = $(man_ADOC_FILES:.adoc=.roff)
BUILT_SOURCES += $(man_ROFF_FILES)
CLEANFILES += $(man_ROFF_FILES) $(man_ROFF_FILES:.roff=)

$(top_builddir)/%.roff: %.adoc
	$(MKDIR_P) $$(dirname $@)
	$(A2X) -v -f manpage $^ -D $(top_builddir)/$$(dirname $@)
	$(INSTALL) -m 644 $(top_builddir)/$(@:.roff=) $(top_builddir)/$@

dist_man1_MANS = \
    doc/clevis-encrypt-tang.1 \
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

endif
