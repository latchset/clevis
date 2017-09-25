nodist_systemdsystemunit_DATA = clevis-luks-askpass.service
dist_systemdsystemunit_DATA = clevis-luks-askpass.path
dist_libexec_SCRIPTS = clevis-luks-askpass

CLEANFILES=clevis-luks-askpass.service
EXTRA_DIST=clevis-luks-askpass.service.in

%: %.in
	$(AM_V_GEN)mkdir -p $(dir $@)
	$(AM_V_GEN)$(SED) \
		-e 's,@libexecdir\@,$(libexecdir),g' \
		$(srcdir)/$@.in > $@
