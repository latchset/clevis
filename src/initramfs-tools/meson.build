initramfs_tools = find_program('update-initramfs', required: get_option('initramfs_tools'))

if initramfs_tools.found()
  initramfstools_dir = '/usr/share/initramfs-tools'
  initramfs_hooks_dir =  '/usr/share/initramfs-tools/hooks'
  initramfs_scripts_dir = '/usr/share/initramfs-tools/scripts'
  initramfs_data = configuration_data()
  initramfs_data.merge_from(data)
  initramfs_data.set('initramfstoolsdir', initramfstools_dir)
  libdir = join_paths(get_option('prefix'), get_option('libdir'))
  initramfs_data.set('libdir', libdir)
  subdir('hooks')
  subdir('scripts')
elif get_option('initramfs_tools').auto()
  warning('Will not install initramfs-tools module due to missing dependencies!')
endif
