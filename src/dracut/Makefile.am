dracutdir = @dracutmodulesdir@/60$(PACKAGE_NAME)
nodist_dracut_SCRIPTS = clevis-hook.sh
dist_dracut_SCRIPTS = module-setup.sh

CLEANFILES=clevis-hook.sh
EXTRA_DIST=clevis-hook.sh.in

%: %.in
	$(AM_V_GEN)mkdir -p $(dir $@)
	$(AM_V_GEN)$(SED) \
		-e 's,@libexedir\@,$(libexecdir),g' \
		$(srcdir)/$@.in > $@
