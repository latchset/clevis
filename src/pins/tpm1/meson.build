cmds = ['tpm_sealdata', 'tpm_unsealdata']

all = true
foreach cmd : cmds
  all = all and find_program(cmd, required: false).found()
endforeach

if all
  bins += join_paths(meson.current_source_dir(), 'clevis-decrypt-tpm1')
  bins += join_paths(meson.current_source_dir(), 'clevis-encrypt-tpm1')
  mans += join_paths(meson.current_source_dir(), 'clevis-encrypt-tpm1.1')
else
  warning('Will not install tpm1 pin due to missing dependencies!')
endif

# Tests.
env = environment()
env.prepend('PATH',
            join_paths(meson.source_root(), 'src'),
            join_paths(meson.source_root(), 'src', 'luks'),
            join_paths(meson.source_root(), 'src', 'luks', 'tests'),
            join_paths(meson.source_root(), 'src', 'pins', 'sss'),
            join_paths(meson.source_root(), 'src', 'pins', 'tang'),
            join_paths(meson.source_root(), 'src', 'pins', 'tpm1'),
            join_paths(meson.source_root(), 'src', 'pins', 'tpm2'),
            join_paths(meson.build_root(), 'src'),
            join_paths(meson.build_root(), 'src', 'luks'),
            join_paths(meson.build_root(), 'src', 'luks', 'tests'),
            join_paths(meson.build_root(), 'src', 'pins', 'sss'),
            join_paths(meson.build_root(), 'src', 'pins', 'tang'),
            join_paths(meson.build_root(), 'src', 'pins', 'tpm1'),
            join_paths(meson.build_root(), 'src', 'pins', 'tpm2'),
            separator: ':'
)
test('pin-tpm1', find_program('pin-tpm1'), env: env, timeout: 300)
