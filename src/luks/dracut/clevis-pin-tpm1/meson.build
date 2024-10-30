dracut = dependency('dracut', required: false)

if dracut.found()
  dracutdir = dracut.get_pkgconfig_variable('dracutmodulesdir') + '/60' + meson.project_name() + '-pin-tpm1'

  configure_file(
    input: 'module-setup.sh.in',
    output: 'module-setup.sh',
    install_dir: dracutdir,
    configuration: data,
  )
else
  warning('Will not install dracut module clevis-pin-tpm1 due to missing dependencies!')
endif
