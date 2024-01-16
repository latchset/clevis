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
    input: 'clevis-hook.sh.in',
    output: 'clevis-hook.sh',
    install_dir: dracutdir,
    configuration: data,
  )

  install_data('clevis-luks-unlocker', install_dir: libexecdir)
else
  warning('Will not install dracut module due to missing dependencies!')
endif
