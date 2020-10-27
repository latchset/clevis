
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

if libcryptsetup.found() and luksmeta.found() and pwmake.found()
  subdir('systemd')
  subdir('udisks2')

  bins += clevis_luks_unbind
  mans += join_paths(meson.current_source_dir(), 'clevis-luks-unbind.1')

  bins += clevis_luks_bind
  mans += join_paths(meson.current_source_dir(), 'clevis-luks-bind.1')

  mans += join_paths(meson.current_source_dir(), 'clevis-luks-unlockers.7')

  bins += join_paths(meson.current_source_dir(), 'clevis-luks-common-functions')

  bins += join_paths(meson.current_source_dir(), 'clevis-luks-list')
  mans += join_paths(meson.current_source_dir(), 'clevis-luks-list.1')

  bins += join_paths(meson.current_source_dir(), 'clevis-luks-unlock')
  mans += join_paths(meson.current_source_dir(), 'clevis-luks-unlock.1')

  bins += join_paths(meson.current_source_dir(), 'clevis-luks-regen')
  mans += join_paths(meson.current_source_dir(), 'clevis-luks-regen.1')

  bins += join_paths(meson.current_source_dir(), 'clevis-luks-report')
  mans += join_paths(meson.current_source_dir(), 'clevis-luks-report.1')

  bins += join_paths(meson.current_source_dir(), 'clevis-luks-edit')
else
  warning('Will not install LUKS support due to missing dependencies!')
endif

# Tests.
subdir('tests')
