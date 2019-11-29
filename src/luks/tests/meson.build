common_functions = configure_file(input: 'tests-common-functions.in',
  output: 'tests-common-functions',
  configuration: luksmeta_data,
  install: false
)

env = environment()
env.prepend('PATH',
  join_paths(meson.source_root(), 'src'),
  join_paths(meson.source_root(), 'src', 'luks'),
  join_paths(meson.source_root(), 'src', 'pins', 'tang'),
  join_paths(meson.source_root(), 'src', 'pins', 'tpm2'),
  meson.current_source_dir(),
  meson.current_build_dir(),
  join_paths(meson.build_root(), 'src'),
  join_paths(meson.build_root(), 'src', 'luks'),
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

# LUKS2 tests go here, and they get included if we get support for it, based
# on the cryptsetup version.
# Binding LUKS2 takes longer, so timeout is increased for a few tests.
if luksmeta_data.get('OLD_CRYPTSETUP') == '0'
  test('bind-wrong-pass-luks2', find_program('bind-wrong-pass-luks2'), env: env)
  test('bind-luks2', find_program('bind-luks2'), env: env, timeout: 60)
  test('unbind-unbound-slot-luks2', find_program('unbind-unbound-slot-luks2'), env: env)
  test('unbind-luks2', find_program('unbind-luks2'), env: env, timeout: 60)
endif
