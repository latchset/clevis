# We use jq for comparing the pin config in the clevis luks list tests.
jq = find_program('jq', required: false)

common_functions = configure_file(input: 'tests-common-functions.in',
  output: 'tests-common-functions',
  configuration: luksmeta_data,
  install: false
)

env = environment()
env.prepend('PATH',
  join_paths(meson.source_root(), 'src'),
  join_paths(meson.source_root(), 'src', 'luks'),
  join_paths(meson.source_root(), 'src', 'pins', 'sss'),
  join_paths(meson.source_root(), 'src', 'pins', 'tang'),
  join_paths(meson.source_root(), 'src', 'pins', 'tpm2'),
  meson.current_source_dir(),
  meson.current_build_dir(),
  join_paths(meson.build_root(), 'src'),
  join_paths(meson.build_root(), 'src', 'luks'),
  join_paths(meson.build_root(), 'src', 'pins', 'sss'),
  join_paths(meson.build_root(), 'src', 'pins', 'tang'),
  join_paths(meson.build_root(), 'src', 'pins', 'tpm2'),
  separator: ':'
)

test('bind-wrong-pass-luks1', find_program('bind-wrong-pass-luks1'), env: env)
test('bind-luks1', find_program('bind-luks1'), env: env)
test('unbind-unbound-slot-luks1', find_program('unbind-unbound-slot-luks1'), env: env)
test('unbind-luks1', find_program('unbind-luks1'), env: env)
test('bind-key-file-non-interactive', find_program('bind-key-file-non-interactive-luks1'), env: env)
test('bind-pass-with-newline', find_program('bind-pass-with-newline-luks1'), env: env)
test('bind-pass-with-newline-keyfile', find_program('bind-pass-with-newline-keyfile-luks1'), env: env)
# Bug #70.
test('bind-already-used-luksmeta-slot', find_program('bind-already-used-luksmeta-slot'), env: env, timeout: 60)

if jq.found()
  test('list-recursive-luks1', find_program('list-recursive-luks1'), env: env)
  test('list-tang-luks1', find_program('list-tang-luks1'), env: env)
  test('list-sss-tang-luks1', find_program('list-sss-tang-luks1'), env: env)
else
  warning('Will not run "clevis luks list" tests due to missing jq dependency')
endif

# LUKS2 tests go here, and they get included if we get support for it, based
# on the cryptsetup version.
# Binding LUKS2 takes longer, so timeout is increased for a few tests.
if luksmeta_data.get('OLD_CRYPTSETUP') == '0'
  test('bind-wrong-pass-luks2', find_program('bind-wrong-pass-luks2'), env: env)
  test('bind-luks2', find_program('bind-luks2'), env: env, timeout: 60)
  test('unbind-unbound-slot-luks2', find_program('unbind-unbound-slot-luks2'), env: env)
  test('unbind-luks2', find_program('unbind-luks2'), env: env, timeout: 60)

  if jq.found()
    test('list-recursive-luks2', find_program('list-recursive-luks2'), env: env, timeout: 60)
    test('list-tang-luks2', find_program('list-tang-luks2'), env: env, timeout: 60)
    test('list-sss-tang-luks2', find_program('list-sss-tang-luks2'), env: env, timeout: 60)
  endif
endif
