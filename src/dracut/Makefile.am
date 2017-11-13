dracutdir = @dracutmodulesdir@/60$(PACKAGE_NAME)
nodist_dracut_SCRIPTS = clevis-hook.sh module-setup.sh
EXTRA_DIST=clevis-hook.sh.in module-setup.sh.in
CLEANFILES=clevis-hook.sh module-setup.sh

%: %.in
	$(AM_V_GEN)mkdir -p $(dir $@)
	$(AM_V_GEN)$(SED) \
		-e 's,@libexecdir\@,$(libexecdir),g' \
		$(srcdir)/$@.in > $@
