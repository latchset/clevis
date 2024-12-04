# We use jq for comparing the pin config in the clevis luks list tests.
jq = find_program('jq', required: false)

# We use cryptsetup for testing LUKS2 binding and saving the token in a
# given token slot.
cryptsetup = find_program('cryptsetup', required: true)

# Use keyctl to check an existing token id can be created from
# kernel keyring password
keyutils = find_program('keyctl', required: false)
keyutils_usable = false
if keyutils.found()
    keyutils_usable = run_command(keyutils, 'session', '-', '/bin/true', capture: false, check: false).returncode() == 0
    if keyutils_usable
        message('keyutils installed')
    else
        warning('keyutils installed, but running fails (are you inside Docker?), unable to test existing token id binding')
    endif
else
    warning('keyutils not installed, unable to test existing token id binding')
endif

common_functions = configure_file(input: 'luks-common-test-functions.in',
  output: 'luks-common-test-functions',
  configuration: luksmeta_data,
  install: false
)

env = environment()
env.prepend('PATH',
  join_paths(meson.source_root(), 'src'),
  join_paths(meson.source_root(), 'src', 'luks'),
  join_paths(meson.source_root(), 'src', 'pins', 'sss'),
  join_paths(meson.source_root(), 'src', 'pins', 'tang'),
  join_paths(meson.source_root(), 'src', 'pins', 'tpm1'),
  join_paths(meson.source_root(), 'src', 'pins', 'tpm2'),
  meson.current_source_dir(),
  meson.current_build_dir(),
  join_paths(meson.build_root(), 'src'),
  join_paths(meson.build_root(), 'src', 'luks'),
  join_paths(meson.build_root(), 'src', 'pins', 'sss'),
  join_paths(meson.build_root(), 'src', 'pins', 'tang'),
  join_paths(meson.build_root(), 'src', 'pins', 'tang', 'tests'),
  join_paths(meson.build_root(), 'src', 'pins', 'tpm1'),
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
test('bind-binary-keyfile', find_program('bind-binary-keyfile-luks1'), env: env)
# Bug #70.
test('bind-already-used-luksmeta-slot', find_program('bind-already-used-luksmeta-slot'), env: env, timeout: 60)
test('bad-sss', find_program('bad-sss'), env: env)

if jq.found()
  test('list-recursive-luks1', find_program('list-recursive-luks1'), env: env)
  test('list-tang-luks1', find_program('list-tang-luks1'), env: env)
  test('list-sss-tang-luks1', find_program('list-sss-tang-luks1'), env: env)
  test('list-multiple-slots-luks1', find_program('list-multiple-slots-luks1'), env: env)
else
  warning('Will not run "clevis luks list" tests due to missing jq dependency')
endif

test('unlock-tang-luks1', find_program('unlock-tang-luks1'), env: env, timeout: 90)
test('assume-yes', find_program('assume-yes'), env: env, timeout: 60)
test('regen-inplace-luks1', find_program('regen-inplace-luks1'), env: env, timeout: 90)
test('regen-not-inplace-luks1', find_program('regen-not-inplace-luks1'), env: env, timeout: 90)
test('report-tang-luks1', find_program('report-tang-luks1'), env: env, timeout: 90)
test('report-sss-luks1', find_program('report-sss-luks1'), env: env, timeout: 90)
test('edit-tang-luks1', find_program('edit-tang-luks1'), env: env, timeout: 150)

test('backup-restore-luks1', find_program('backup-restore-luks1'), env: env, timeout: 60)
test('pass-tang-luks1', find_program('pass-tang-luks1'), env: env, timeout: 60)
test('bind-luks1-avoid-luksmeta-corruption', find_program('bind-luks1-avoid-luksmeta-corruption'), env: env, timeout: 60)

# LUKS2 tests go here, and they get included if we get support for it, based
# on the cryptsetup version.
# Binding LUKS2 takes longer, so timeout is increased for a few tests.
if luksmeta_data.get('OLD_CRYPTSETUP') == '0'
  test('bind-wrong-pass-luks2', find_program('bind-wrong-pass-luks2'), env: env)
  test('bind-luks2', find_program('bind-luks2'), env: env, timeout: 60)
  test('unbind-unbound-slot-luks2', find_program('unbind-unbound-slot-luks2'), env: env)
  test('unbind-luks2', find_program('unbind-luks2'), env: env, timeout: 60)

  if keyutils.found() and keyutils_usable and luksmeta_data.get('OLD_CRYPTSETUP_EXISTING_TOKEN_ID') == '0'
    test('bind-luks2-ext-token', find_program('bind-luks2-ext-token'), env: env, timeout: 60)
  endif

  if jq.found()
    test('list-recursive-luks2', find_program('list-recursive-luks2'), env: env, timeout: 60)
    test('list-tang-luks2', find_program('list-tang-luks2'), env: env, timeout: 60)
    test('list-sss-tang-luks2', find_program('list-sss-tang-luks2'), env: env, timeout: 60)
    test('list-multiple-slots-luks2', find_program('list-multiple-slots-luks2'), env: env, timeout: 60)
  endif

  test('unlock-tang-luks2', find_program('unlock-tang-luks2'), env: env, timeout: 120)
  test('assume-yes-luks2', find_program('assume-yes-luks2'), env: env, timeout: 90)
  test('regen-inplace-luks2', find_program('regen-inplace-luks2'), env: env, timeout: 120)
  test('regen-not-inplace-luks2', find_program('regen-not-inplace-luks2'), env: env, timeout: 120)
  test('report-tang-luks2', find_program('report-tang-luks2'), env: env, timeout: 120)
  test('report-sss-luks2', find_program('report-sss-luks2'), env: env, timeout: 120)
  test('edit-tang-luks2', find_program('edit-tang-luks2'), env: env, timeout: 210)

  test('backup-restore-luks2', find_program('backup-restore-luks2'), env: env, timeout: 120)
  test('pass-tang-luks2', find_program('pass-tang-luks2'), env: env, timeout: 60)
endif

test('unlock-arbitrary-parameter', find_program('unlock-arbitrary-parameter'), env: env)

