bashcomp = dependency('bash-completion', required: false)

if get_option('bashcompdir') != '' or bashcomp.found()
  if get_option('bashcompdir') != ''
    bashcompdir = get_option('bashcompdir')
  else
    bashcompdir = bashcomp.get_variable(pkgconfig: 'completionsdir')
  endif
  install_data('clevis', install_dir: bashcompdir)
else
  warning('Will not install bash completion due to missing dependencies!')
endif
