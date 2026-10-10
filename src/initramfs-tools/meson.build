initramfs_tools = find_program('update-initramfs', required: false)

if initramfs_tools.found()
  initramfstools_dir = '/usr/share/initramfs-tools'
  initramfs_hooks_dir =  '/usr/share/initramfs-tools/hooks'
  initramfs_scripts_dir = '/usr/share/initramfs-tools/scripts'
  zfs_initramfs_load_key_scripts_dir = '/etc/zfs/initramfs-tools-load-key.d'
  initramfs_data = configuration_data()
  initramfs_data.merge_from(data)
  initramfs_data.set('initramfstoolsdir', initramfstools_dir)
  libdir = join_paths(get_option('prefix'), get_option('libdir'))
  initramfs_data.set('libdir', libdir)
  subdir('hooks')
  subdir('scripts')
else
  warning('Will not install initramfs-tools module due to missing dependencies!')
endif
