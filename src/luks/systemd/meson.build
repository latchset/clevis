systemd = dependency('systemd', required: false)

if systemd.found()
  subdir('dracut')

  unitdir = systemd.get_pkgconfig_variable('systemdsystemunitdir')

  configure_file(
    input: 'clevis-luks-askpass.service.in',
    output: 'clevis-luks-askpass.service',
    install_dir: unitdir,
    configuration: data,
  )

  install_data('clevis-luks-askpass.path', install_dir: unitdir)
  install_data('clevis-luks-askpass', install_dir: libexecdir)
else
  warning('Will not install systemd support due to missing dependencies!')
endif
