# Tests
env = environment()
env.prepend('PATH',
  join_paths(meson.source_root(), 'src'),
  join_paths(meson.source_root(), 'src', 'pins', 'tpm1'),
  join_paths(meson.source_root(), 'src', 'pins', 'tpm1', 'tests'),
  join_paths(meson.build_root(), 'src'),
  join_paths(meson.build_root(), 'src', 'luks', 'tests'),
  join_paths(meson.build_root(), 'src', 'pins', 'tang', 'tests'),
  join_paths(meson.build_root(), 'src', 'pins', 'tpm1'),
  join_paths(meson.build_root(), 'src', 'pins', 'tpm1', 'tests'),
  separator: ':'
)

tpm1_data = configuration_data()
tpm1_data.merge_from(data)

tpm_version = find_program('tpm_version', '/usr/sbin/tpm_version', required: false)
tpm_sealdata = find_program('tpm_sealdata', '/usr/sbin/tpm_sealdata', required: false)
tpm_unsealdata = find_program('tpm_unsealdata', '/usr/sbin/tpm_unsealdata', required: false)
tpm_takeownership = find_program('tpm_takeownership', '/usr/sbin/tpm_takeownership', required: false)
tcsd = find_program('tcsd', '/usr/sbin/tcsd', required: false)
swtpm = find_program('swtpm', '/usr/bin/swtpm', required: false)
swtpm_setup = find_program('swtpm_setup', '/usr/bin/swtpm_setup', required: false)

tpm1_data.set('TPM_VERSION_BIN', tpm_version.found() ? tpm_version.path() : '')
tpm1_data.set('TPM_SEALDATA_BIN', tpm_sealdata.found() ? tpm_sealdata.path() : '')
tpm1_data.set('TPM_UNSEALDATA_BIN', tpm_unsealdata.found() ? tpm_unsealdata.path() : '')
tpm1_data.set('TPM_TAKEOWNERSHIP_BIN', tpm_takeownership.found() ? tpm_takeownership.path() : '')
tpm1_data.set('TCSD_BIN', tcsd.found() ? tcsd.path() : '')
tpm1_data.set('SWTPM_BIN', swtpm.found() ? swtpm.path() : '')
tpm1_data.set('SWTPM_SETUP_BIN', swtpm_setup.found() ? swtpm_setup.path() : '')

configure_file(
  input: 'tpm1-common-test-functions.in',
  output: 'tpm1-common-test-functions',
  configuration: tpm1_data,
)

patch_data = configuration_data()
cc = meson.get_compiler('c')
has___xstat = cc.has_header_symbol('sys/stat.h', '__xstat', args: ['-D_GNU_SOURCE'])

patch_data.set('HAS___XSTAT', has___xstat)

tcsd_patch_src = configure_file(
  input: 'tcsd-patch.c.in',
  output: 'tcsd-patch.c',
  configuration: patch_data
)

libdl_dep = dependency('dl', required: true)
tcsd_patch = shared_library('tcsd-patch', tcsd_patch_src,
  dependencies: libdl_dep,
  install: false)
tcsd_patch_path = tcsd_patch.full_path()
env.prepend('TCSD_PATCH_LIB', tcsd_patch_path)

test('pin-tpm1-hw', find_program('pin-tpm1-hw'), env: env, timeout: 120)
test('pin-tpm1-sw', find_program('pin-tpm1-sw'), env: env, timeout: 120)
