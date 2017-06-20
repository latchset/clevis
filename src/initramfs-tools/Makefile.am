initramfstoolsdir = @initramfstoolsmodulesdir@
nodist_initramfstools_SCRIPTS = hooks/clevis scripts/local-bottom/clevis \
	scripts/local-top/clevis
EXTRA_DIST=hooks/clevis.in scripts/local-bottom/clevis.in scripts/local-top/clevis.in
CLEANFILES=hooks/clevis scripts/local-bottom/clevis scripts/local-top/clevis

%: %.in
	$(AM_V_GEN)mkdir -p $(dir $@)
	$(AM_V_GEN)$(SED) \
		-e 's,@initramfstoolsdir@,$(initramfstoolsdir),g' \
		-e 's,@bindir\@,$(bindir),g' \
		$(srcdir)/$@.in > $@

install-nodist_initramfstoolsSCRIPTS:
	$(AM_V_GEN)mkdir -p $(initramfstoolsdir)
	for i in $(nodist_initramfstools_SCRIPTS); do      \
		$(install_sh) -c -m 555 $$i $(initramfstoolsdir)/$$i;    \
	done
