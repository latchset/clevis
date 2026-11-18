dracut = dependency('dracut', required: false)

if dracut.found()
  dracutdir = dracut.get_pkgconfig_variable('dracutmodulesdir') + '/50' + meson.project_name() + '-zfs'

  configure_file(
    input: 'module-setup.sh.in',
    output: 'module-setup.sh',
    install_dir: dracutdir,
    configuration: data,
  )

  configure_file(
    input: 'clevis-zfs-unlocker.in',
    output: 'clevis-zfs-unlocker',
    install_dir: dracutdir,
    configuration: data,
  )

  install_data(
    'clevis-zfs-wrapper',
    'clevis-zfs-wrapper-hook.sh',
    install_dir: dracutdir,
  )
else
  warning('Will not install dracut module clevis-zfs due to missing dependencies!')
endif
