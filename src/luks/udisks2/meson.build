udisks2 = dependency('udisks2', required: get_option('udisks'))
audit = dependency('audit', version: '>=2.7.8', required: get_option('udisks'))
gio = dependency('gio-2.0', required: get_option('udisks'))

if udisks2.found() and audit.found() and gio.found()
  autostartdir = join_paths(sysconfdir, 'xdg', 'autostart')

  configure_file(
    input: 'clevis-luks-udisks2.desktop.in',
    output: 'clevis-luks-udisks2.desktop',
    install_dir: autostartdir,
    configuration: data,
  )

  executable('clevis-luks-udisks2',
    ['clevis-luks-udisks2.c', 'token-to-jwe.c'],
    dependencies: [udisks2, luksmeta, audit, jansson],
    install_dir: libexecdir,
    install: true,
  )
elif get_option('udisks').auto()
  warning('Will not build udisks2 support due to missing dependencies!')
endif

if jansson.found()
  test_token_to_jwe = executable('test-token-to-jwe',
    ['test-token-to-jwe.c', 'token-to-jwe.c'],
    dependencies: [jansson],
  )
  test('token-to-jwe', test_token_to_jwe)
endif
