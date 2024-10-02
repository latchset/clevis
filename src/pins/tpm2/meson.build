cmds = ['tpm2_createprimary', ['tpm2_pcrread', 'tpm2_pcrlist'],
        'tpm2_createpolicy', 'tpm2_create', 'tpm2_flushcontext', 'tpm2_load',
        'tpm2_unseal']

all = true
foreach cmd : cmds
  all = all and find_program(cmd, required: false).found()
endforeach

if all
  bins += join_paths(meson.current_source_dir(), 'clevis-decrypt-tpm2')
  bins += join_paths(meson.current_source_dir(), 'clevis-encrypt-tpm2')
  mans += join_paths(meson.current_source_dir(), 'clevis-encrypt-tpm2.1')
  subdir('tests')
else
  warning('Will not install tpm2 pin due to missing dependencies!')
endif
