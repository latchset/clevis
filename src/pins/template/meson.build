#%# This controls build and test
#%#
#%# Feel free to peek into other tests to get an idea what can be done.
#%#
#%# Possibly you'll need some extra programs, probe for them.

#%# curl is just an example
curl = find_program('curl', required: false)
#%# dracut and initramfs_tools are needed for early userland
dracut = dependency('dracut', required: false)
initramfs_tools = find_program('update-initramfs', required: false)

if curl.found()
#%# BUild the programs
  bins += join_paths(meson.current_source_dir(), 'clevis-decrypt-@pin@')
  bins += join_paths(meson.current_source_dir(), 'clevis-encrypt-@pin@')
#%# and the manpage
  mans += join_paths(meson.current_source_dir(), 'clevis-encrypt-@pin@.1')

#%# Set up a test environment
  env = environment()
  env.append('PATH',
    join_paths(meson.source_root(), 'src'),
    meson.current_source_dir(),
    '/usr/libexec',
    libexecdir,
    separator: ':'
  )

#%# Run the test.
  test('pin-@pin@', find_program('./pin-@pin@'), env: env)
else
  warning('Will not install @pin@ pin due to missing dependencies!')
endif

#%# dracut support
if dracut.found()
  dracutdir = dracut.get_pkgconfig_variable('dracutmodulesdir') + '/60' + meson.project_name() + '-pin-@pin@'
#?# In general, substituation is not needed but it's better to
#?# stay flexible.
  configure_file(
    input: 'dracut.module-setup.sh.in',
    output: 'module-setup.sh',
    install_dir: dracutdir,
    configuration: data,
  )
else
  warning('Will not install dracut module clevis-pin-@pin@ due to missing dependencies!')
endif

#%# initramfs support
if initramfs_tools.found()
  initramfstools_dir = '/usr/share/initramfs-tools'
  initramfs_hooks_dir =  '/usr/share/initramfs-tools/hooks'
  initramfs_data = configuration_data()
  initramfs_data.merge_from(data)
  initramfs_data.set('initramfstoolsdir', initramfstools_dir)
  configure_file(
    input: 'initramfs.in',
    output: 'clevis-pin-@pin@',
    install_dir: initramfs_hooks_dir,
    configuration: initramfs_data,
  )
else
  warning('Will not install initramfs module clevis-pin-@pin@ due to missing dependencies!')
endif
