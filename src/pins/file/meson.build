
dracut = dependency('dracut', required: false)
initramfs_tools = find_program('update-initramfs', required: false)

bins += join_paths(meson.current_source_dir(), 'clevis-decrypt-file')
bins += join_paths(meson.current_source_dir(), 'clevis-encrypt-file')
mans += join_paths(meson.current_source_dir(), 'clevis-encrypt-file.1')

env = environment()
env.append('PATH',
  join_paths(meson.source_root(), 'src'),
  meson.current_source_dir(),
  '/usr/libexec',
  libexecdir,
  separator: ':'
)

test('pin-file', find_program('./pin-file'), env: env)

if dracut.found()
  dracutdir = dracut.get_pkgconfig_variable('dracutmodulesdir') + '/60' + meson.project_name() + '-pin-file'
  configure_file(
    input: 'dracut.module-setup.sh.in',
    output: 'module-setup.sh',
    install_dir: dracutdir,
    configuration: data,
  )
else
  warning('Will not install dracut module clevis-pin-file due to missing dependencies!')
endif

if initramfs_tools.found()
  initramfstools_dir = '/usr/share/initramfs-tools'
  initramfs_hooks_dir =  '/usr/share/initramfs-tools/hooks'
  initramfs_data = configuration_data()
  initramfs_data.merge_from(data)
  initramfs_data.set('initramfstoolsdir', initramfstools_dir)
  configure_file(
    input: 'initramfs.in',
    output: 'clevis-pin-file',
    install_dir: initramfs_hooks_dir,
    configuration: initramfs_data,
  )
else
  warning('Will not install initramfs module clevis-pin-file due to missing dependencies!')
endif
