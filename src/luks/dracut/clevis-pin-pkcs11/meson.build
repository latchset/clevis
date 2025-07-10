dracut = dependency('dracut', required: false)

if dracut.found()
  dracutdir = dracut.get_pkgconfig_variable('dracutmodulesdir') + '/60' + meson.project_name() + '-pin-pkcs11'

  configure_file(
    input: 'module-setup.sh.in',
    output: 'module-setup.sh',
    install_dir: dracutdir,
    configuration: data,
  )

  configure_file(
    input: 'clevis-pkcs11-hook.sh.in',
    output: 'clevis-pkcs11-hook.sh',
    install_dir: dracutdir,
    configuration: data,
    )
  install_data('clevis-pkcs11-prehook.sh', install_dir: dracutdir)

else
  warning('Will not install dracut module clevis-pin-pkcs11 due to missing dependencies!')
endif
