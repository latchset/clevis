cmds = ['createprimary', 'pcrlist', 'createpolicy', 'create', 'load', 'unseal']

all = true
foreach cmd : cmds
  all = all and find_program('tpm2_' + cmd, required: false).found()
endforeach

if all
  bins += join_paths(meson.current_source_dir(), 'clevis-decrypt-tpm2')
  bins += join_paths(meson.current_source_dir(), 'clevis-encrypt-tpm2')
  mans += join_paths(meson.current_source_dir(), 'clevis-encrypt-tpm2.1')
else
  warning('Will not install tpm2 pin due to missing dependencies!')
endif