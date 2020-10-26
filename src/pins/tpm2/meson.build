cmds = ['tpm2_createprimary', ['tpm2_pcrread', 'tpm2_pcrlist'],
        'tpm2_createpolicy', 'tpm2_create', 'tpm2_load', 'tpm2_unseal']

all = true
foreach cmd : cmds
  all = all and find_program(cmd, required: false).found()
endforeach

if all
  bins += join_paths(meson.current_source_dir(), 'clevis-decrypt-tpm2')
  bins += join_paths(meson.current_source_dir(), 'clevis-encrypt-tpm2')
  mans += join_paths(meson.current_source_dir(), 'clevis-encrypt-tpm2.1')
else
  warning('Will not install tpm2 pin due to missing dependencies!')
endif

# Tests.
env = environment()
env.prepend('PATH',
  join_paths(meson.source_root(), 'src'),
  join_paths(meson.source_root(), 'src', 'luks'),
  join_paths(meson.source_root(), 'src', 'luks', 'tests'),
  join_paths(meson.source_root(), 'src', 'pins', 'sss'),
  join_paths(meson.source_root(), 'src', 'pins', 'tang'),
  join_paths(meson.source_root(), 'src', 'pins', 'tpm2'),
  join_paths(meson.build_root(), 'src'),
  join_paths(meson.build_root(), 'src', 'luks'),
  join_paths(meson.build_root(), 'src', 'luks', 'tests'),
  join_paths(meson.build_root(), 'src', 'pins', 'sss'),
  join_paths(meson.build_root(), 'src', 'pins', 'tang'),
  join_paths(meson.build_root(), 'src', 'pins', 'tpm2'),
  separator: ':'
)
test('pin-tpm2', find_program('pin-tpm2'), env: env, timeout: 120)
