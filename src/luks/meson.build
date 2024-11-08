
luksmeta_data = configuration_data()
luksmeta = dependency('luksmeta', version: '>=8', required: false)

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

libcryptsetup_ext_token_id = dependency('libcryptsetup', version: '>=2.6.0', required: false)
if libcryptsetup_ext_token_id.found()
    luksmeta_data.set('OLD_CRYPTSETUP_EXISTING_TOKEN_ID', '0')
    message('cryptsetup version supports existing token id')
else
    luksmeta_data.set('OLD_CRYPTSETUP_EXISTING_TOKEN_ID', '1')
    warning('cryptsetup version does not support existing token id')
endif

clevis_luks_common_functions = configure_file(
  input: 'clevis-luks-common-functions.in',
  output: 'clevis-luks-common-functions',
  configuration: luksmeta_data
)

clevis_luks_tpm1_functions = configure_file(
  input: 'clevis-luks-tpm1-functions.in',
  output: 'clevis-luks-tpm1-functions',
  configuration: data
)

clevis_luks_unbind = configure_file(input: 'clevis-luks-unbind.in',
               output: 'clevis-luks-unbind',
               configuration: luksmeta_data)

# SystemD dependencies checked here, used both in systemd and dracut subdirs
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

if libcryptsetup.found() and luksmeta.found()
  subdir('systemd')
  subdir('dracut')
  subdir('udisks2')

  bins += clevis_luks_unbind
  mans += join_paths(meson.current_source_dir(), 'clevis-luks-unbind.1')

  bins += join_paths(meson.current_source_dir(), 'clevis-luks-bind')
  mans += join_paths(meson.current_source_dir(), 'clevis-luks-bind.1')

  mans += join_paths(meson.current_source_dir(), 'clevis-luks-unlockers.7')

  bins += clevis_luks_common_functions

  bins += join_paths(meson.current_source_dir(), 'clevis-luks-list')
  mans += join_paths(meson.current_source_dir(), 'clevis-luks-list.1')

  bins += join_paths(meson.current_source_dir(), 'clevis-luks-unlock')
  mans += join_paths(meson.current_source_dir(), 'clevis-luks-unlock.1')

  bins += join_paths(meson.current_source_dir(), 'clevis-luks-regen')
  mans += join_paths(meson.current_source_dir(), 'clevis-luks-regen.1')

  bins += join_paths(meson.current_source_dir(), 'clevis-luks-report')
  mans += join_paths(meson.current_source_dir(), 'clevis-luks-report.1')

  bins += join_paths(meson.current_source_dir(), 'clevis-luks-edit')
  mans += join_paths(meson.current_source_dir(), 'clevis-luks-edit.1')

  bins += join_paths(meson.current_source_dir(), 'clevis-luks-pass')
  mans += join_paths(meson.current_source_dir(), 'clevis-luks-pass.1')

  install_data(clevis_luks_tpm1_functions, install_dir: libexecdir)
else
  warning('Will not install LUKS support due to missing dependencies!')
endif

# Tests.

if not meson.is_cross_build()
  subdir('tests')
endif
