cmds = ['tpm_sealdata', 'tpm_unsealdata']

all = true
foreach cmd : cmds
  all = all and find_program(cmd, required: false).found()
endforeach

if all
  bins += join_paths(meson.current_source_dir(), 'clevis-decrypt-tpm1')
  bins += join_paths(meson.current_source_dir(), 'clevis-encrypt-tpm1')
  mans += join_paths(meson.current_source_dir(), 'clevis-encrypt-tpm1.1')

  libdl_dep = dependency('dl', required: true)
  libclevis_tpm1_tcsd_preload = shared_library('clevis-tpm1-tcsd-preload', 'clevis-tpm1-tcsd-preload.c',
    dependencies: libdl_dep,
    install_dir: libdir,
    install: true)

  subdir('tests')
else
  warning('Will not install tpm1 pin due to missing dependencies!')
endif
