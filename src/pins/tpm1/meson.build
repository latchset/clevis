cmds = ['tpm_sealdata', 'tpm_unsealdata']

all = true
foreach cmd : cmds
  all = all and find_program(cmd, required: false).found()
endforeach

if all
  bins += join_paths(meson.current_source_dir(), 'clevis-decrypt-tpm1')
  bins += join_paths(meson.current_source_dir(), 'clevis-encrypt-tpm1')
  mans += join_paths(meson.current_source_dir(), 'clevis-encrypt-tpm1.1')
  subdir('tests')
else
  warning('Will not install tpm1 pin due to missing dependencies!')
endif
