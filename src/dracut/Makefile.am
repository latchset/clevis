dracutdir = @dracutmodulesdir@/60$(PACKAGE_NAME)
nodist_dracut_SCRIPTS = module-setup.sh
EXTRA_DIST=module-setup.sh.in
CLEANFILES=module-setup.sh

%: %.in
	$(AM_V_GEN)mkdir -p $(dir $@)
	$(AM_V_GEN)$(SED) \
		-e 's,@libexecdir\@,$(libexecdir),g' \
		$(srcdir)/$@.in > $@
