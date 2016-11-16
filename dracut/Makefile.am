dracutdir = @dracutmodulesdir@/60$(PACKAGE_NAME)
dist_dracut_SCRIPTS = module-setup.sh clevis-hook.sh

%: %.in
	$(AM_V_GEN)$(SED) -e 's,@clevisdir\@,$(libexecdir)/$(PACKAGE_NAME),g' $(srcdir)/$@.in > $@
