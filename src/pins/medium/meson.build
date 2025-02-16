
losetup = find_program('losetup', required: false)
mkfs = find_program('mkfs.ext4', required: false)
mount = find_program('mount', required: false)
dracut = dependency('dracut', required: false)
initramfs_tools = find_program('update-initramfs', required: false)

bins += join_paths(meson.current_source_dir(), 'clevis-decrypt-medium')
bins += join_paths(meson.current_source_dir(), 'clevis-encrypt-medium')
mans += join_paths(meson.current_source_dir(), 'clevis-encrypt-medium.1')

if losetup.found() and mkfs.found() and mount.found()
  env = environment()
  env.append('PATH',
    join_paths(meson.source_root(), 'src'),
    meson.current_source_dir(),
    '/usr/libexec',
    libexecdir,
    separator: ':'
  )

  test('pin-medium', find_program('./pin-medium'), env: env)
else
  warning('Will not test medium pin due to missing programs')
endif

if dracut.found()
  dracutdir = dracut.get_pkgconfig_variable('dracutmodulesdir') + '/60' + meson.project_name() + '-pin-medium'
  configure_file(
    input: 'dracut.module-setup.sh.in',
    output: 'module-setup.sh',
    install_dir: dracutdir,
    configuration: data,
  )
else
  warning('Will not install dracut module clevis-pin-medium due to missing dependencies!')
endif

if initramfs_tools.found()
  initramfstools_dir = '/usr/share/initramfs-tools'
  initramfs_hooks_dir =  '/usr/share/initramfs-tools/hooks'
  initramfs_data = configuration_data()
  initramfs_data.merge_from(data)
  initramfs_data.set('initramfstoolsdir', initramfstools_dir)
  configure_file(
    input: 'initramfs.in',
    output: 'clevis-pin-medium',
    install_dir: initramfs_hooks_dir,
    configuration: initramfs_data,
  )
else
  warning('Will not install initramfs module clevis-pin-medium due to missing dependencies!')
endif
