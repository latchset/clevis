systemd = dependency('systemd', required: false)
systemdutildir = systemd.found() ? systemd.get_pkgconfig_variable('systemdutildir', default: '') : ''

sd_reply_pass = find_program(
  (systemdutildir != '') ? join_paths(systemdutildir, 'systemd-reply-password') : '',
  join_paths(get_option('prefix'), get_option('libdir'), 'systemd', 'systemd-reply-password'),
  join_paths(get_option('prefix'), 'lib', 'systemd', 'systemd-reply-password'),
  join_paths('/', 'usr', get_option('libdir'), 'systemd', 'systemd-reply-password'),
  join_paths('/', 'usr', 'lib', 'systemd', 'systemd-reply-password'),
  required: false
)

if systemd.found() and sd_reply_pass.found()
  data.set('SYSTEMD_REPLY_PASS', sd_reply_pass.path())

  unitdir = systemd.get_pkgconfig_variable('systemdsystemunitdir')
  tcsdoverridedir = join_paths(unitdir, 'tcsd.service.d')

  configure_file(
    input: 'clevis-luks-askpass.service.in',
    output: 'clevis-luks-askpass.service',
    install_dir: unitdir,
    configuration: data,
  )
  configure_file(
    input: 'clevis-luks-pkcs11-askpass.service.in',
    output: 'clevis-luks-pkcs11-askpass.service',
    install_dir: unitdir,
    configuration: data,
  )
  configure_file(
    input: 'clevis-luks-askpass.in',
    output: 'clevis-luks-askpass',
    install_dir: libexecdir,
    configuration: data
  )
  configure_file(
    input: 'clevis-luks-pkcs11-askpass.in',
    output: 'clevis-luks-pkcs11-askpass',
    install_dir: libexecdir,
    configuration: data
  )
  configure_file(
    input: 'clevis-luks-pkcs11-askpin.in',
    output: 'clevis-luks-pkcs11-askpin',
    install_dir: libexecdir,
    configuration: data
  )

  install_data('clevis-luks-askpass.path', install_dir: unitdir)
  install_data('clevis-luks-pkcs11-askpass.socket', install_dir: unitdir)
  install_data('clevis-tcsd.conf', install_dir: tcsdoverridedir)
else
  warning('Will not install systemd support due to missing dependencies!')
endif
