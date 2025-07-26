# Tests.
env = environment()
env.prepend('PATH',
  join_paths(meson.source_root(), 'src'),
  join_paths(meson.source_root(), 'src', 'luks'),
  join_paths(meson.source_root(), 'src', 'luks', 'tests'),
  join_paths(meson.source_root(), 'src', 'pins', 'sss'),
  join_paths(meson.source_root(), 'src', 'pins', 'tang'),
  join_paths(meson.source_root(), 'src', 'pins', 'tpm2'),
  join_paths(meson.source_root(), 'src', 'pins', 'tpm2', 'tests'),
  join_paths(meson.build_root(), 'src'),
  join_paths(meson.build_root(), 'src', 'luks'),
  join_paths(meson.build_root(), 'src', 'luks', 'tests'),
  join_paths(meson.build_root(), 'src', 'pins', 'sss'),
  join_paths(meson.build_root(), 'src', 'pins', 'tang'),
  join_paths(meson.build_root(), 'src', 'pins', 'tpm2'),
  join_paths(meson.build_root(), 'src', 'pins', 'tpm2', 'tests'),
  separator: ':'
)

tpm2_data = configuration_data()
tpm2_data.merge_from(data)

socat = find_program('socat', required: false)
swtpm = find_program('swtpm', '/usr/bin/swtpm', required: false)
swtpm_setup = find_program('swtpm_setup', '/usr/bin/swtpm_setup', required: false)

tpm2_data.set('SOCAT_BIN', socat.found() ? socat.path() : '')
tpm2_data.set('SWTPM_BIN', swtpm.found() ? swtpm.path() : '')
tpm2_data.set('SWTPM_SETUP_BIN', swtpm_setup.found() ? swtpm_setup.path() : '')

configure_file(
  input: 'tpm2-common-test-functions.in',
  output: 'tpm2-common-test-functions',
  configuration: tpm2_data,
)

test('pin-tpm2-hw', find_program('pin-tpm2-hw'), env: env, timeout: 120)
test('pin-tpm2-sw', find_program('pin-tpm2-sw'), env: env, timeout: 120)
