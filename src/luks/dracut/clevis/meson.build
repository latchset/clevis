dracut = dependency('dracut', required: false)

if dracut.found()
  dracutdir = dracut.get_pkgconfig_variable('dracutmodulesdir') + '/60' + meson.project_name()

  configure_file(
    input: 'module-setup.sh.in',
    output: 'module-setup.sh',
    install_dir: dracutdir,
    configuration: data,
  )

  configure_file(
    input: 'clevis-cleanup.in',
    output: 'clevis-cleanup',
    install_dir: dracutdir,
    configuration: data,
  )

  configure_file(
    input: 'clevis-password-unlocker.in',
    output: 'clevis-password-unlocker',
    install_dir: dracutdir,
    configuration: data,
  )

  configure_file(
    input: 'clevis-password-unlocker-prepare.in',
    output: 'clevis-password-unlocker-prepare',
    install_dir: dracutdir,
    configuration: data,
  )

  install_data('clevis-cleanup-hook.sh', install_dir: dracutdir)
  install_data('clevis-password-unlocker-hook.sh', install_dir: dracutdir)
  install_data('clevis-online-hook.sh', install_dir: dracutdir)
else
  warning('Will not install dracut module due to missing dependencies!')
endif
