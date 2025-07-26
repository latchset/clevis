if systemd.found() and sd_reply_pass.found()
  systemd_data = configuration_data()
  systemd_data.merge_from(data)
  systemd_data.set('SYSTEMD_REPLY_PASS', sd_reply_pass.path())

  unitdir = systemd.get_pkgconfig_variable('systemdsystemunitdir')
  tcsdoverridedir = join_paths(unitdir, 'tcsd.service.d')

  configure_file(
    input: 'clevis-luks-askpass.service.in',
    output: 'clevis-luks-askpass.service',
    install_dir: unitdir,
    configuration: systemd_data,
  )
  configure_file(
    input: 'clevis-luks-pkcs11-askpass.service.in',
    output: 'clevis-luks-pkcs11-askpass.service',
    install_dir: unitdir,
    configuration: systemd_data,
  )
  configure_file(
    input: 'clevis-luks-askpass.in',
    output: 'clevis-luks-askpass',
    install_dir: libexecdir,
    configuration: systemd_data
  )
  configure_file(
    input: 'clevis-luks-pkcs11-askpass.in',
    output: 'clevis-luks-pkcs11-askpass',
    install_dir: libexecdir,
    configuration: systemd_data
  )
  configure_file(
    input: 'clevis-luks-pkcs11-askpin.in',
    output: 'clevis-luks-pkcs11-askpin',
    install_dir: libexecdir,
    configuration: systemd_data
  )

  install_data('clevis-luks-askpass.path', install_dir: unitdir)
  install_data('clevis-luks-pkcs11-askpass.socket', install_dir: unitdir)
  install_data('clevis-tcsd.conf', install_dir: tcsdoverridedir)
else
  warning('Will not install systemd support due to missing dependencies!')
endif
