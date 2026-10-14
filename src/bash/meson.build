bashcomp = dependency('bash-completion', required: false)

if bashcomp.found()
  bashcompdir = bashcomp.get_variable(pkgconfig : 'completionsdir')
  install_data('clevis', install_dir: bashcompdir)
else
  warning('Will not install bash completion due to missing dependencies!')
endif
