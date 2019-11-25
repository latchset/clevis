
luksmeta_data = configuration_data()
luksmeta = dependency('luksmeta', version: '>=8', required: false)
pwmake = find_program('pwmake', required: false)

libcryptsetup = dependency('libcryptsetup', version: '>=2.0.4', required: false)
if libcryptsetup.found()
    luksmeta_data.set('OLD_CRYPTSETUP', '0')
else
    libcryptsetup = dependency('libcryptsetup', version: '>=2.0.2', required: false)
    if libcryptsetup.found()
        luksmeta_data.set('OLD_CRYPTSETUP', '1')
        warning('Old version of cryptsetup found, forcing use of luksmeta')
    endif
endif

clevis_luks_bind = configure_file(input: 'clevis-luks-bind.in',
               output: 'clevis-luks-bind',
               configuration: luksmeta_data)

clevis_luks_unbind = configure_file(input: 'clevis-luks-unbind.in',
               output: 'clevis-luks-unbind',
               configuration: luksmeta_data)
clevis_luks_unlock = configure_file(input: 'clevis-luks-unlock.in',
               output: 'clevis-luks-unlock',
               configuration: luksmeta_data)
if libcryptsetup.found() and luksmeta.found() and pwmake.found()
  subdir('systemd')
  subdir('udisks2')

  bins += clevis_luks_unbind
  mans += join_paths(meson.current_source_dir(), 'clevis-luks-unbind.1')

  bins += clevis_luks_unlock
  mans += join_paths(meson.current_source_dir(), 'clevis-luks-unlock.1')

  bins += clevis_luks_bind
  mans += join_paths(meson.current_source_dir(), 'clevis-luks-bind.1')

  mans += join_paths(meson.current_source_dir(), 'clevis-luks-unlockers.7')
else
  warning('Will not install LUKS support due to missing dependencies!')
endif

# Tests.
subdir('tests')
